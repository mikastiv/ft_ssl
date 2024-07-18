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

bool
ft_memcmp(Buffer a, Buffer b);

char
ft_lower(char c);

u64
ft_hextol(const char* value);

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
buf(u8* ptr, u64 len);

Buffer
read_all_fd(int fd, u64 size_hint);

u64
get_filesize(int fd);

u32
read_u32(u8* buffer);

u64
read_u64(u8* buffer);

u32
read_u32_be(u8* buffer);

u64
read_u48_be(u8* buffer);

u64
read_u64_be(u8* buffer);

u32
read_u24_be(u8* buffer);

u32
read_u16_be(u8* buffer);

void
print_error(void);

bool
is_space(u8 c);

void
parse_hex(Buffer str, Buffer out, bool* err);

void
print_hex(Buffer str);

bool
get_random_bytes(Buffer buffer);

typedef struct {
    int fd;
} Random;

bool
random_init(Random* random);

void
random_deinit(Random* random);

u64
random_number(Random* random, u64 min, u64 max);

#define MAX_PASSWORD_SIZE 128

bool
read_password(Buffer buffer, bool verify);

int
get_infile_fd(const char* filename);

int
get_outfile_fd(const char* filename);

u64
power(u64 n, u64 k);

u64
power_mod(u64 x, u64 y, u64 mod);
