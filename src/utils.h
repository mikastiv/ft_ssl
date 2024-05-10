#pragma once

#include "types.h"

#define array_len(array) (sizeof(array) / sizeof(array[0]))

u64
ft_strlen(const char* str);

i64
ft_strcmp(const char* s1, const char* s2);

void
ft_memcpy(Buffer dst, Buffer src);

void
ft_memset(Buffer dst, u8 value);

u32
rotate_left(u32 value, u32 shift);
