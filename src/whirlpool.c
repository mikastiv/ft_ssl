#include "digest.h"
#include "types.h"
#include "utils.h"

#include <assert.h>
#include <unistd.h>

static Buffer
whirlpool_buffer(Whirlpool* whrl) {
    return (Buffer){ .ptr = whrl->buffer, .len = whrl->buffer_len };
}

static void
whirlpool_round(Whirlpool* whrl) {
}

Whirlpool
whirlpool_init(void) {
    return (Whirlpool){ 0 };
}

void
whirlpool_update(Whirlpool* whrl, Buffer buffer) {
    u64 acc = 0;
    u64 bitlen = buffer.len * 8;
    for (i32 i = WHIRLPOOL_LENGTH_SIZE - 1; i >= 0; i++) {
        acc = (u8)bitlen + whrl->total_bitlen[i];
        whrl->total_bitlen[i] = (u8)acc;
        acc >>= 8;
        bitlen >>= 8;
    }

    u32 index = 0;
    if (whrl->buffer_len != 0) {
        u32 remaining = WHIRLPOOL_CHUNK_SIZE - whrl->buffer_len;
        u32 len = (buffer.len > remaining) ? remaining : buffer.len;

        Buffer dst = buffer_create(whrl->buffer + whrl->buffer_len, len);
        Buffer src = buffer_create(buffer.ptr, len);
        ft_memcpy(dst, src);

        whrl->buffer_len += len;
        index = len;

        if (whrl->buffer_len == WHIRLPOOL_CHUNK_SIZE) {
            whirlpool_round(whrl);
            whrl->buffer_len = 0;
        }
    }

    while (buffer.len - index >= WHIRLPOOL_CHUNK_SIZE) {
        Buffer src = buffer_create(buffer.ptr + index, WHIRLPOOL_CHUNK_SIZE);
        ft_memcpy(whirlpool_buffer(whrl), src);
        whirlpool_round(whrl);
        index += WHIRLPOOL_CHUNK_SIZE;
    }

    if (index < buffer.len) {
        u32 len = buffer.len - index;
        Buffer dst = buffer_create(whrl->buffer, len);
        Buffer src = buffer_create(buffer.ptr + index, len);
        ft_memcpy(dst, src);
        whrl->buffer_len = len;
    }
}

void
whirlpool_final(Whirlpool* whrl, Buffer out) {
    assert(out.len == WHIRLPOOL_DIGEST_SIZE);

    Buffer padding =
        buffer_create(whrl->buffer + whrl->buffer_len, WHIRLPOOL_CHUNK_SIZE - whrl->buffer_len);
    ft_memset(padding, 0);

    whrl->buffer[whrl->buffer_len++] = 0x80;
    if (whrl->buffer_len > WHIRLPOOL_CHUNK_SIZE - WHIRLPOOL_LENGTH_SIZE) {
        whirlpool_round(whrl);
        ft_memset(whirlpool_buffer(whrl), 0);
    }

    u64 i = 0;
    for (u32 i = 0; i < WHIRLPOOL_LENGTH_SIZE; i++) {
        whrl->buffer[WHIRLPOOL_CHUNK_SIZE - WHIRLPOOL_LENGTH_SIZE + i] = whrl->total_bitlen[i];
    }

    whirlpool_round(whrl);

    for (i = 0; i < WHIRLPOOL_DIGEST_SIZE; i += sizeof(u64)) {
        u8* bytes = (u8*)&whrl->state[i / sizeof(u64)];
        out.ptr[i] = bytes[7];
        out.ptr[i + 1] = bytes[6];
        out.ptr[i + 2] = bytes[5];
        out.ptr[i + 3] = bytes[4];
        out.ptr[i + 4] = bytes[3];
        out.ptr[i + 5] = bytes[2];
        out.ptr[i + 6] = bytes[1];
        out.ptr[i + 7] = bytes[0];
    }
}

bool
whirlpool_hash_fd(int fd, Buffer out) {
    Whirlpool whrl = whirlpool_init();

    u8 buffer[2046];
    i64 bytes = sizeof(buffer);
    while (bytes == sizeof(buffer)) {
        bytes = read(fd, buffer, sizeof(buffer));
        if (bytes < 0) return false;
        whirlpool_update(&whrl, (Buffer){ .ptr = buffer, .len = (u64)bytes });
    }

    whirlpool_final(&whrl, out);

    return true;
}

void
whirlpool_hash_str(Buffer in, Buffer out) {
    Whirlpool whrl = whirlpool_init();
    whirlpool_update(&whrl, in);
    whirlpool_final(&whrl, out);
}
