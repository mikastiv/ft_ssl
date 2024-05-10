#include "utils.h"

#include <assert.h>

u64
ft_strlen(const char* str) {
    u64 len = 0;
    while (str[len]) len++;
    return len;
}

i64
ft_strcmp(const char* s1, const char* s2) {
    while (*s1 == *s2) {
        if (*s1 == 0) return (0);
        ++s1;
        ++s2;
    }
    return (*s1 - *s2);
}

void
ft_memcpy(Buffer dst, Buffer src) {
    assert(dst.len == src.len);

    u64 len = dst.len;
    while (len) {
        *dst.ptr = *src.ptr;
        dst.ptr++;
        src.ptr++;
        len--;
    }
}

void
ft_memset(Buffer dst, u8 value) {
    u64 len = dst.len;
    while (len) {
        *dst.ptr = value;
        dst.ptr++;
        len--;
    }
}

u32
rotate_left(u32 value, u32 shift) {
    assert(shift < 32);
    return (value << shift) | (value >> (32 - shift));
}

u32
rotate_right(u32 value, u32 shift) {
    assert(shift < 32);
    return (value >> shift) | (value << (32 - shift));
}

Buffer
str(const char* s) {
    return (Buffer){ .ptr = (u8*)s, .len = ft_strlen(s) };
}

Buffer
buffer_create(u8* ptr, u64 len) {
    return (Buffer){ .ptr = ptr, .len = len };
}
