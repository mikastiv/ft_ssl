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
rotate_left32(u32 value, u32 shift);

u32
rotate_right32(u32 value, u32 shift);

u64
rotate_left64(u64 value, u64 shift);

u64
rotate_right64(u64 value, u64 shift);

u32
byte_swap32(u32 value);

u64
byte_swap64(u64 value);

Buffer
str(const char* s);

Buffer
buffer_create(u8* ptr, u64 len);

Buffer
stdin_to_buffer(void);

u32
read_u32(u8* buffer);

u64
read_u64(u8* buffer);

u64
read_u48_be(u8* buffer);

u32
read_u24_be(u8* buffer);

u32
read_u16_be(u8* buffer);
