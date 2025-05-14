// libpng_write_fuzzer.cc
// -----------------------------------------------------------------------------
// A leak-free, allocation-bounded **write-side** harness for libpng, in the
// same spirit as the upstream read fuzzer.
//
// * Keeps LeakSanitizer enabled at all times.
// * Uses a PNG_CLEANUP macro so every early-return frees libpng state.
// * Installs a `limited_malloc` that refuses > 8 MiB single allocations.
// * Explicitly releases std::vector capacity and, on glibc, calls
//   `malloc_trim(0)` so the working-set really shrinks between iterations.
//
// Copyright © 2025 Your Name
// SPDX-License-Identifier: BSD-2-Clause
// -----------------------------------------------------------------------------

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>
#include <algorithm>          // std::min

#define PNG_INTERNAL
#include <png.h>
#include <zlib.h>

#if defined(__GLIBC__)
# include <malloc.h>          // malloc_trim
#endif

/*----------------------------------------------------------------------------*/
/*  Helpers                                                                    */
/*----------------------------------------------------------------------------*/
#define BE32(p) ((uint32_t)(p)[0] << 24 | (uint32_t)(p)[1] << 16 | \
                 (uint32_t)(p)[2] <<  8 | (uint32_t)(p)[3])

#define BE16(p) ((uint16_t)(p)[0] << 8  | (uint16_t)(p)[1])

static void png_noop_error(png_structp, png_const_charp) {}
static void png_noop_warn (png_structp, png_const_charp) {}

static void write_data_fn(png_structp png_ptr,
                          png_bytep   data,
                          png_size_t  len)
{
  auto *out = static_cast<std::vector<uint8_t>*>(png_get_io_ptr(png_ptr));
  out->insert(out->end(), data, data + len);
}

/* libpng may occasionally try to allocate huge buffers (e.g. for large        */
/* interlace passes).  Reject anything above 8 MiB to avoid OOM.               */
static void* limited_malloc(png_structp, png_alloc_size_t sz)
{
  return sz > 8000000 ? nullptr : malloc(sz);}
static void  default_free  (png_structp, png_voidp p) { free(p); }

/*----------------------------------------------------------------------------*/
/*  Aggregate object so we can destroy everything from one pointer            */
/*----------------------------------------------------------------------------*/
struct PngWriteHandler {
  png_structp png_ptr  = nullptr;
  png_infop   info_ptr = nullptr;
  std::vector<png_bytep> row_ptrs;
  std::vector<std::vector<png_byte>> rows;
  std::vector<uint8_t> outbuf;

  ~PngWriteHandler() {
    if (png_ptr)
      png_destroy_write_struct(&png_ptr, info_ptr ? &info_ptr : nullptr);
    png_ptr  = nullptr;
    info_ptr = nullptr;
  }
};

/* Clean-up macro identical in spirit to the read-side harness. */
#define PNG_CLEANUP                          \
  do {                                       \
    handler.~PngWriteHandler();              \
    return 0;                                \
  } while (0)

/*----------------------------------------------------------------------------*/
/*  Fuzzer entry-point                                                        */
/*----------------------------------------------------------------------------*/
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 24)             /* need space for params + at least 1 row byte  */
    return 0;

  uint32_t width  = BE32(data + 0);
  uint32_t height = BE32(data + 4);
  if (!width || !height || width > 64 || height > 64)
    return 0;

  PngWriteHandler handler;

  /*-------------------------------------------------------------------------*/
  /* 1) create libpng objects                                                */
  /*-------------------------------------------------------------------------*/
  handler.png_ptr = png_create_write_struct(
      PNG_LIBPNG_VER_STRING, nullptr, png_noop_error, png_noop_warn);
  if (!handler.png_ptr)
    return 0;

  handler.info_ptr = png_create_info_struct(handler.png_ptr);
  if (!handler.info_ptr)
    PNG_CLEANUP;

  /* custom allocator */
  png_set_mem_fn(handler.png_ptr, nullptr, limited_malloc, default_free);

  /* every libpng error jumps back here */
  if (setjmp(png_jmpbuf(handler.png_ptr)))
    PNG_CLEANUP;

  /*-------------------------------------------------------------------------*/
  /* 2) parameter decoding from fuzzer buffer                                */
  /*-------------------------------------------------------------------------*/
  int interlace   = (data[8] & 1) ? PNG_INTERLACE_ADAM7 : PNG_INTERLACE_NONE;
  int filter_mask = data[9] & (PNG_FILTER_NONE | PNG_FILTER_SUB |
                               PNG_FILTER_UP  | PNG_FILTER_AVG |
                               PNG_FILTER_PAETH);
  int comp_level  = 1 + (data[10] % 9);
  int comp_strat  = (data[11] & 1) ? Z_DEFAULT_STRATEGY : Z_FILTERED;

  png_set_IHDR(handler.png_ptr, handler.info_ptr,
               width, height,
               8,                        /* bit depth                  */
               PNG_COLOR_TYPE_RGBA,
               interlace,
               PNG_COMPRESSION_TYPE_DEFAULT,
               PNG_FILTER_TYPE_DEFAULT);

  png_set_compression_level   (handler.png_ptr, comp_level);
  png_set_compression_strategy(handler.png_ptr, comp_strat);
  png_set_filter              (handler.png_ptr, PNG_FILTER_TYPE_BASE,
                               filter_mask);
  png_set_interlace_handling  (handler.png_ptr);

  /* ancillary chunks ------------------------------------------------------ */
  if (size >= 19) {
    png_time t;
    uint16_t yr = BE16(data + 12);
    t.year   = yr ? yr : 2025;
    t.month  = (data[14] % 12) + 1;
    t.day    = (data[15] % 31) + 1;
    t.hour   = data[16] % 24;
    t.minute = data[17] % 60;
    t.second = data[18] % 60;
    png_set_tIME(handler.png_ptr, handler.info_ptr, &t);
  }

  if (size > 19) {
    float gamma = 0.1f + (data[19] / 255.0f) * 2.0f;
    png_set_gAMA(handler.png_ptr, handler.info_ptr, gamma);
  }

  if (size > 20) {
    int intent = (data[20] & 1) ? PNG_sRGB_INTENT_PERCEPTUAL
                                : PNG_sRGB_INTENT_SATURATION;
    png_set_sRGB(handler.png_ptr, handler.info_ptr, intent);
  }

  png_set_cHRM_fixed(handler.png_ptr, handler.info_ptr,
                     31270, 32900, 64000, 33000,
                     30000, 60000, 15000,  6000);

  if (size > 21) {
    png_text txt;
    txt.compression = PNG_TEXT_COMPRESSION_NONE;
    txt.key         = (png_charp)"FuzzComment";
    txt.text        = (png_charp)"generated by write harness";
    png_set_text(handler.png_ptr, handler.info_ptr, &txt, 1);
  }

  if (size > 22)
    png_set_pHYs(handler.png_ptr, handler.info_ptr, 300, 300,
                 PNG_RESOLUTION_METER);

  /*-------------------------------------------------------------------------*/
  /* 3) prepare row buffers                                                  */
  /*-------------------------------------------------------------------------*/
  size_t rowbytes = png_get_rowbytes(handler.png_ptr, handler.info_ptr);
  size_t data_off = 16;                /* pixel data starts here            */

  handler.rows.assign(height, std::vector<png_byte>(rowbytes));

  for (uint32_t y = 0; y < height; ++y) {
    size_t avail   = (data_off + y * rowbytes < size)
                   ? size - (data_off + y * rowbytes)
                   : 0;
    size_t n       = std::min(rowbytes, avail);
    memcpy(handler.rows[y].data(),
           data + data_off + y * rowbytes, n);
    if (n < rowbytes)
      memset(handler.rows[y].data() + n, 0, rowbytes - n);
  }

  handler.row_ptrs.resize(height);
  for (uint32_t y = 0; y < height; ++y)
    handler.row_ptrs[y] = handler.rows[y].data();

  /*-------------------------------------------------------------------------*/
  /* 4) optional unknown chunk                                               */
  /*-------------------------------------------------------------------------*/
  size_t used = data_off + height * rowbytes;
  if (size > used + 4) {
    size_t uc_len = std::min<size_t>(size - used, 32);
    png_unknown_chunk uc;
    memcpy(uc.name, data + 0, 4);
    uc.name[4]  = 0;
    uc.data     = (png_bytep)(data + used);
    uc.size     = (png_uint_32)uc_len;
    uc.location = PNG_AFTER_IDAT;

    png_set_unknown_chunks(handler.png_ptr, handler.info_ptr, &uc, 1);
    png_set_unknown_chunk_location(handler.png_ptr, handler.info_ptr,
                                   0, PNG_AFTER_IDAT);
  }

  /*-------------------------------------------------------------------------*/
  /* 5) perform the write                                                    */
  /*-------------------------------------------------------------------------*/
  png_set_write_fn(handler.png_ptr, &handler.outbuf, write_data_fn, nullptr);

  png_write_info(handler.png_ptr, handler.info_ptr);

  if (data[23] & 1) {
    png_write_image(handler.png_ptr, handler.row_ptrs.data());
  } else {
    for (uint32_t y = 0; y < height; ++y)
      png_write_row(handler.png_ptr, handler.row_ptrs[y]);
  }

  png_write_end(handler.png_ptr, handler.info_ptr);

  /*-------------------------------------------------------------------------*/
  /* 6) give memory back to the system                                       */
  /*-------------------------------------------------------------------------*/
  handler.outbuf.clear();              handler.outbuf.shrink_to_fit();
  for (auto &r : handler.rows) { r.clear(); r.shrink_to_fit(); }
  handler.rows.clear();               handler.rows.shrink_to_fit();
  handler.row_ptrs.clear();           handler.row_ptrs.shrink_to_fit();

#if defined(__GLIBC__)
  malloc_trim(0);
#endif

  return 0;   /* handler destructor frees libpng state                       */
}
