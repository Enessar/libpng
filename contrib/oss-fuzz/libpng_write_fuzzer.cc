// libpng_write_fuzzer.cc
#include <png.h>
#include <vector>
#include <cstdint>
#include <cstring>   // for memcpy, memset

// No-op error/warning handlers avoid abort().
static void png_noop_error(png_structp, png_const_charp) {}
static void png_noop_warn(png_structp, png_const_charp) {}

// In-memory write callback: collect output bytes.
static void write_data_fn(png_structp png_ptr,
                          png_bytep data,
                          png_size_t length) {
  auto* out = static_cast<std::vector<uint8_t>*>(
      png_get_io_ptr(png_ptr));
  out->insert(out->end(), data, data + length);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data,
                                      size_t size) {
  // Need at least 8 bytes for width+height
  if (size < 8) return 0;

  uint32_t width  = (data[0]<<24)|(data[1]<<16)|(data[2]<<8)|data[3];
  uint32_t height = (data[4]<<24)|(data[5]<<16)|(data[6]<<8)|data[7];

  // Bail on zero or overly large dimensions
  if (width == 0 || height == 0 || width > 64 || height > 64)
    return 0;

  // Create write struct with no-op handlers
  png_structp png_ptr = png_create_write_struct(
      PNG_LIBPNG_VER_STRING,
      nullptr,
      png_noop_error,
      png_noop_warn);
  if (!png_ptr) return 0;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    png_destroy_write_struct(&png_ptr, nullptr);
    return 0;
  }

  // 1) Set up IO callback
  std::vector<uint8_t> outbuf;
  png_set_write_fn(png_ptr, &outbuf, write_data_fn, nullptr);

  // 2) Set IHDR so png_get_rowbytes() works
  png_set_IHDR(png_ptr, info_ptr,
               width, height,
               8,                    // bit depth
               PNG_COLOR_TYPE_RGBA,  // color type
               PNG_INTERLACE_NONE,
               PNG_COMPRESSION_TYPE_DEFAULT,
               PNG_FILTER_TYPE_DEFAULT);

  // 3) Allocate our own row buffers
  size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
  std::vector<std::vector<png_byte>> safe_rows(height,
                                               std::vector<png_byte>(rowbytes));
  // Copy from fuzzer + zero-pad
  size_t pixel_data_offset = 8;
  for (uint32_t y = 0; y < height; ++y) {
    size_t avail = (size > pixel_data_offset + y*rowbytes)
                   ? size - (pixel_data_offset + y*rowbytes)
                   : 0;
    size_t to_copy = std::min(rowbytes, avail);
    memcpy(safe_rows[y].data(),
           data + pixel_data_offset + y*rowbytes,
           to_copy);
    if (to_copy < rowbytes) {
      memset(safe_rows[y].data() + to_copy, 0, rowbytes - to_copy);
    }
  }

  // Build the array of row pointers
  std::vector<png_bytep> row_ptrs(height);
  for (uint32_t y = 0; y < height; ++y)
    row_ptrs[y] = safe_rows[y].data();

  // 4) Write PNG
  png_write_info(png_ptr, info_ptr);
  png_write_image(png_ptr, row_ptrs.data());
  png_write_end(png_ptr, info_ptr);

  // 5) Cleanup
  png_destroy_write_struct(&png_ptr, &info_ptr);
  (void)outbuf.size();  // suppress unused

  return 0;
}
