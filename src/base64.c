#include "arena.h"
#include "cipher.h"
#include "globals.h"
#include "ssl.h"
#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

static const char* base64_alpha =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char padding = '=';

static u32
alpha_index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == padding) return 0;
    if (c == '/') return 63;
    return (u32)-1;
}

Buffer
base64_encode(Buffer input) {
    u64 chunks = input.len / 3;
    u64 extra = input.len % 3;

    u64 size = chunks * 4 + (extra > 0 ? 4 : 0);
    u64 newlines = size / 64;
    size += newlines;

    Buffer buffer = buf(arena_alloc(&arena, size), size);
    ft_memset(buffer, 0);

    u64 i = 0;
    u64 j = 0;
    u64 accum = 0;
    for (; i + 2 < input.len; i += 3, j += 4, accum += 4) {
        if (accum != 0 && accum % 64 == 0) {
            buffer.ptr[j] = '\n';
            j++;
        }

        u32 bytes = read_u24_be(&input.ptr[i]);
        buffer.ptr[j + 0] = base64_alpha[(bytes >> 18) & 0x3F];
        buffer.ptr[j + 1] = base64_alpha[(bytes >> 12) & 0x3F];
        buffer.ptr[j + 2] = base64_alpha[(bytes >> 6) & 0x3F];
        buffer.ptr[j + 3] = base64_alpha[(bytes >> 0) & 0x3F];
    }

    switch (extra) {
        case 2: {
            u32 bytes = read_u16_be(&input.ptr[i]);
            buffer.ptr[j + 0] = base64_alpha[(bytes >> 10) & 0x3F];
            buffer.ptr[j + 1] = base64_alpha[(bytes >> 4) & 0x3F];
            buffer.ptr[j + 2] = base64_alpha[(bytes & 0xF) << 2];
            buffer.ptr[j + 3] = padding;
        } break;
        case 1: {
            u32 bytes = input.ptr[i];
            buffer.ptr[j + 0] = base64_alpha[(bytes >> 2) & 0x3F];
            buffer.ptr[j + 1] = base64_alpha[(bytes & 0x3) << 4];
            buffer.ptr[j + 2] = padding;
            buffer.ptr[j + 3] = padding;
        } break;
    }

    return buffer;
}

static Buffer
remove_whitespace(Buffer input) {
    u64 i = 0;
    for (u64 j = 0; j < input.len; j++) {
        if (!is_space(input.ptr[j])) input.ptr[i++] = input.ptr[j];
    }
    return buf(input.ptr, i);
}

Buffer
base64_decode(Buffer input) {
    input = remove_whitespace(input);
    u64 chunks = input.len / 4;
    if (input.len % 4 != 0) return (Buffer){ 0 };

    u64 output_size = chunks * 3;
    Buffer buffer = buf(arena_alloc(&arena, output_size), output_size);
    ft_memset(buffer, 0);

    for (u64 i = 0, j = 0; i < input.len; i += 4, j += 3) {
        u32 bytes = 0;
        for (u64 k = 0; k < 4; k++) {
            bytes <<= 6;
            u32 index = alpha_index(input.ptr[i + k]);
            if (index > 63) goto error;
            bytes |= index;
        }

        if (input.ptr[i] == padding || input.ptr[i + 1] == padding) goto error;

        u32 padding_count = (input.ptr[i + 2] == padding) + (input.ptr[i + 3] == padding);
        if (padding_count) {
            if (input.ptr[i + 2] == padding && input.ptr[i + 3] != padding) goto error;
            buffer.len -= padding_count;
        }

        buffer.ptr[j] = (bytes >> 16) & 0xFF;
        buffer.ptr[j + 1] = (padding_count < 2) ? (bytes >> 8) & 0xFF : 0;
        buffer.ptr[j + 2] = (padding_count < 1) ? bytes & 0xFF : 0;
    }

    return buffer;

error:
    return (Buffer){ 0 };
}

bool
base64(Base64Options* options) {
    bool result = false;

    if (options->decode && options->encode) {
        dprintf(STDERR_FILENO, "%s: cannot encode and decode at the same time\n", progname);
        return false;
    }
    if (!options->decode && !options->encode) options->encode = true;

    int in_fd = get_infile_fd(options->input_file);
    int out_fd = get_outfile_fd(options->output_file);

    if (in_fd == -1 || out_fd == -1) {
        print_error();
        goto base64_err;
    }

    u64 size_hint = get_filesize(in_fd);
    Buffer input = read_all_fd(in_fd, size_hint);
    if (!input.ptr) {
        print_error();
        goto base64_err;
    }

    Buffer res;
    if (options->decode) {
        res = base64_decode(input);
    } else {
        res = base64_encode(input);
    }

    if (!res.ptr) {
        dprintf(STDERR_FILENO, "%s: invalid input\n", progname);
        goto base64_err;
    }

    (void)write(out_fd, res.ptr, res.len);
    if (options->encode) (void)write(out_fd, "\n", 1);

    result = true;

base64_err:
    if (options->output_file && out_fd != -1) close(out_fd);
    if (options->input_file && in_fd != -1) close(in_fd);
    return result;
}
