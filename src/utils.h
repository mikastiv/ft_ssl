#pragma once

#include "types.h"

#include <assert.h>

#define array_len(array) (sizeof(array) / sizeof(array[0]))

u64
ft_strlen(const char* str);

i64
ft_strcmp(const char* s1, const char* s2);

void
ft_memcpy(Buffer dst, Buffer src);

inline u32
rotate_left(u32 value, u32 shift) {
    assert(shift < 32);
    return (value << shift) | (value >> (32 - shift));
}
