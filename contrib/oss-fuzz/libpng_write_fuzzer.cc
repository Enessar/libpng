// libpng_write_fuzzer.cc
#include <png.h>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cstdlib>   // for free()


// Exactly mirror the read‐fuzzer’s PNG_CLEANUP macro:
#define PNG_CLEANUP_WRITE(image, buf) \
  do {                                  \
    free(buf);                          \
    png_image_free(&image);             \
  } while (0)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // We need 8 bytes of input for width+height.
  if (size < 8) return 0;

  // Decode big-endian width & height.
  uint32_t w = (data[0]<<24)|(data[1]<<16)|(data[2]<<8)|data[3];
  uint32_t h = (data[4]<<24)|(data[5]<<16)|(data[6]<<8)|data[7];
  if (!w || !h || w > 64 || h > 64)
    return 0;

  // 1) Set up the high-level write struct
  png_image image;
  memset(&image, 0, sizeof(image));
  image.version = PNG_IMAGE_VERSION;
  image.width   = w;
  image.height  = h;
  image.format  = PNG_FORMAT_RGBA;  // 8 bits × 4 channels

  // 2) Build one big RGBA pixel buffer from the remainder of the fuzzer input
  size_t pixel_bytes = size_t(w) * h * 4;
  std::vector<png_byte> pixels(pixel_bytes);
  size_t avail = size - 8;
  memcpy(pixels.data(), data + 8, std::min(avail, pixel_bytes));

  // 3) Write to a malloc’d buffer: this allocs & frees ALL internal libpng state.
  void*             out_buf  = nullptr;
  png_alloc_size_t  out_size = 0;  // use the correct unsigned long typedef
  if (!png_image_write_to_memory(
        &image,
        &out_buf, (png_alloc_size_t*)&out_size,
        0,              /* convert_to_8bit – unused */
        pixels.data(),
        0,              /* row_stride – packed */
        nullptr))       /* colormap – none */ 
  {
    // On write error, libpng cleaned up after itself; no leaks.
    return 0;
  }

  // 4) CLEANUP (frees out_buf + every internal allocation in png_image_write)
  PNG_CLEANUP_WRITE(image, out_buf);
  return 0;
}
