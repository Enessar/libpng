#include <png.h>
#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>

// No-op error/warning handlers to avoid aborting
static void png_noop_error(png_structp, png_const_charp) {}
static void png_noop_warn(png_structp, png_const_charp) {}

const uint32_t kMaxWidth = 64;
const uint32_t kMaxHeight = 64;
const size_t kMaxRowbytes = 1 << 20;    // 1 MB per row max
const size_t kMaxOutBufSize = 4 << 20;  // 4 MB output max

static void write_data_fn(png_structp png_ptr, png_bytep data, png_size_t length) {
  auto* out = static_cast<std::vector<uint8_t>*>(png_get_io_ptr(png_ptr));
  if (out->size() + length > kMaxOutBufSize) {
    png_error(png_ptr, "output buffer too large");
    return;
  }
  out->insert(out->end(), data, data + length);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 8) return 0;

  uint32_t width  = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
  uint32_t height = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];

  if (width == 0 || height == 0 || width > kMaxWidth || height > kMaxHeight)
    return 0;

  png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr,
                                                png_noop_error, png_noop_warn);
  if (!png_ptr) return 0;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    png_destroy_write_struct(&png_ptr, nullptr);
    return 0;
  }

  // Prevent libpng from internally allocating massive buffers
  png_set_user_limits(png_ptr, kMaxWidth, kMaxHeight);

  std::vector<uint8_t> outbuf;
  png_set_write_fn(png_ptr, &outbuf, write_data_fn, nullptr);

  png_set_IHDR(png_ptr, info_ptr,
               width, height,
               8, PNG_COLOR_TYPE_RGBA,
               PNG_INTERLACE_NONE,
               PNG_COMPRESSION_TYPE_DEFAULT,
               PNG_FILTER_TYPE_DEFAULT);

  size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
  if (rowbytes > kMaxRowbytes) {
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
  }

  // Flat pixel buffer (no nested vectors)
  std::vector<uint8_t> flat_rows(rowbytes * height, 0);
  size_t pixel_data_offset = 8;

  for (uint32_t y = 0; y < height; ++y) {
    size_t offset = pixel_data_offset + y * rowbytes;
    size_t to_copy = std::min(rowbytes, (offset < size) ? size - offset : 0);
    memcpy(&flat_rows[y * rowbytes], data + offset, to_copy);
  }

  std::vector<png_bytep> row_ptrs(height);
  for (uint32_t y = 0; y < height; ++y)
    row_ptrs[y] = &flat_rows[y * rowbytes];

  png_write_info(png_ptr, info_ptr);
  png_write_image(png_ptr, row_ptrs.data());
  png_write_end(png_ptr, info_ptr);

  png_destroy_write_struct(&png_ptr, &info_ptr);
  return 0;
}
