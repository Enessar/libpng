
// libpng_write_fuzzer.cc
#include <png.h>
#include <stddef.h>
#include <stdint.h>
#include <vector>

// A simple in-memory write callback: collect bytes into a buffer
static void write_data_fn(png_structp png_ptr, png_bytep data, png_size_t length) {
    std::vector<uint8_t>* out =
        static_cast<std::vector<uint8_t>*>(png_get_io_ptr(png_ptr));
    out->insert(out->end(), data, data + length);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // 1. Parse input as an uncompressed image: width/height + raw pixels
    if (size < 8) return 0;
    uint32_t width  = (data[0]  << 24) | (data[1]  << 16)
                    | (data[2]  <<  8) |  data[3];
    uint32_t height = (data[4]  << 24) | (data[5]  << 16)
                    | (data[6]  <<  8) |  data[7];
    size_t expected = size_t(width) * height * 4 + 8;
    if (expected != size) return 0;

    png_structp png_ptr = png_create_write_struct(
        PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (!png_ptr) return 0;
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_write_struct(&png_ptr, nullptr);
        return 0;
    }

    // 2. Set up our in-memory writer
    std::vector<uint8_t> outbuf;
    png_set_write_fn(png_ptr, &outbuf, write_data_fn, nullptr);

    // 3. Set image header
    png_set_IHDR(png_ptr, info_ptr,
                 width, height,
                 8,                    // bit depth
                 PNG_COLOR_TYPE_RGBA,  // color type
                 PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_DEFAULT,
                 PNG_FILTER_TYPE_DEFAULT);

    // 4. Write the PNG: header + data + end
    png_write_info(png_ptr, info_ptr);

    // 5. Point to the first pixel & write rows
    png_const_bytep pixels = data + 8; 
    std::vector<png_bytep> row_ptrs(height);
    for (uint32_t y = 0; y < height; ++y) {
        // cast away const here, since libpng API wants non-const pointers
        row_ptrs[y] = const_cast<png_bytep>(
            pixels + size_t(y) * width * 4);
    }

    png_write_image(png_ptr, row_ptrs.data());
    png_write_end(png_ptr, info_ptr);

    // 6. Tear down
    png_destroy_write_struct(&png_ptr, &info_ptr);
    (void)outbuf.size();  // silence unused-variable warnings
    return 0;
}
