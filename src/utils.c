#include "utils.h"
#include "arena.h"
#include "globals.h"

#ifdef __APPLE__
#include <readpassphrase.h>
#else
#include <bsd/readpassphrase.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

Buffer
ft_strstr(Buffer hay, Buffer needle) {
    if (needle.len > hay.len) return (Buffer){ 0 };

    u64 iter = hay.len - needle.len;
    for (u64 i = 0; i <= iter; i++) {
        u8* ptr = hay.ptr + i;
        if (ft_memcmp(buf(ptr, needle.len), needle)) {
            return buf(ptr, needle.len);
        }
    }

    return (Buffer){ 0 };
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

bool
ft_memcmp(Buffer a, Buffer b) {
    if (a.len != b.len) return false;
    for (u64 i = 0; i < a.len; i++) {
        if (a.ptr[i] != b.ptr[i]) return false;
    }
    return true;
}

char
ft_lower(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A' + 'a';
    return c;
}

u64
ft_hextol(const char* value) {
    u64 i = 0;
    if (ft_memcmp(str("0x"), buf((u8*)value, 2)) || ft_memcmp(str("0X"), buf((u8*)value, 2))) {
        i += 2;
    }

    u64 len = ft_strlen(value);
    u64 out = 0;
    while (i < len) {
        char c = ft_lower(value[i]);

        if (c >= '0' && c <= '9')
            c -= '0';
        else if (c >= 'a' && c <= 'f')
            c = (c - 'a') + 10;
        else
            return out;

        out *= 16;
        out += c;

        i++;
    }

    return out;
}

u32
rotate_left32(u32 value, u32 shift) {
    assert(shift < 32);
    return (value << shift) | (value >> (32 - shift));
}

u32
rotate_right32(u32 value, u32 shift) {
    assert(shift < 32);
    return (value >> shift) | (value << (32 - shift));
}

u64
rotate_left64(u64 value, u64 shift) {
    assert(shift < 64);
    return (value << shift) | (value >> (64 - shift));
}

u64
rotate_right64(u64 value, u64 shift) {
    assert(shift < 64);
    return (value >> shift) | (value << (64 - shift));
}

u32
byte_swap32(u32 value) {
    u32 a = (value << 24) & 0xFF000000u;
    u32 b = (value << 8) & 0x00FF0000u;
    u32 c = (value >> 8) & 0x0000FF00u;
    u32 d = (value >> 24) & 0x000000FFu;
    return a | b | c | d;
}

u64
byte_swap64(u64 value) {
    u64 a = (value << 56) & 0xFF00000000000000ull;
    u64 b = (value << 40) & 0x00FF000000000000ull;
    u64 c = (value << 24) & 0x0000FF0000000000ull;
    u64 d = (value << 8) & 0x000000FF00000000ull;
    u64 e = (value >> 8) & 0x00000000FF000000ull;
    u64 f = (value >> 24) & 0x0000000000FF0000ull;
    u64 g = (value >> 40) & 0x000000000000FF00ull;
    u64 h = (value >> 56) & 0x00000000000000FFull;
    return a | b | c | d | e | f | g | h;
}

Buffer
str(const char* s) {
    return (Buffer){ .ptr = (u8*)s, .len = ft_strlen(s) };
}

Buffer
buf(u8* ptr, u64 len) {
    return (Buffer){ .ptr = ptr, .len = len };
}

Buffer
read_all_fd(int fd, u64 size_hint) {
    u64 capacity = size_hint > 0 ? size_hint : 2048;
    Buffer str = { .ptr = arena_alloc(&arena, capacity + 1), .len = 0 };

    u8 buffer[2048];
    i64 bytes = sizeof(buffer);
    while (bytes > 0) {
        bytes = read(fd, buffer, sizeof(buffer));
        if (bytes < 0) return (Buffer){ 0 };

        u64 remaining = capacity - str.len;

        if ((u64)bytes > remaining) {
            u64 rest = bytes - remaining;
            capacity = (capacity * 2 > rest) ? capacity * 2 : rest;

            u8* ptr = arena_alloc(&arena, capacity + 1);

            ft_memcpy(buf(ptr, str.len), str);
            str.ptr = ptr;
        }

        ft_memcpy(buf(str.ptr + str.len, bytes), buf(buffer, bytes));
        str.len += bytes;
    }

    str.ptr[str.len] = 0;

    return str;
}

u64
get_filesize(int fd) {
    struct stat filestat;

    int result = fstat(fd, &filestat);
    if (result != 0) return 0;

    return filestat.st_size;
}

u32
read_u32(u8* buffer) {
    u32 out = 0;

    out |= (u32)buffer[0];
    out |= (u32)buffer[1] << 8;
    out |= (u32)buffer[2] << 16;
    out |= (u32)buffer[3] << 24;

    return out;
}

u64
read_u64(u8* buffer) {
    u64 out = 0;

    out |= (u64)buffer[0];
    out |= (u64)buffer[1] << 8;
    out |= (u64)buffer[2] << 16;
    out |= (u64)buffer[3] << 24;
    out |= (u64)buffer[4] << 32;
    out |= (u64)buffer[5] << 40;
    out |= (u64)buffer[6] << 48;
    out |= (u64)buffer[7] << 56;

    return out;
}

u32
read_u32_be(u8* buffer) {
    u32 out = 0;

    out |= (u32)buffer[3];
    out |= (u32)buffer[2] << 8;
    out |= (u32)buffer[1] << 16;
    out |= (u32)buffer[0] << 24;

    return out;
}

u64
read_u48_be(u8* buffer) {
    u64 out = 0;

    out |= (u64)buffer[5];
    out |= (u64)buffer[4] << 8;
    out |= (u64)buffer[3] << 16;
    out |= (u64)buffer[2] << 24;
    out |= (u64)buffer[1] << 32;
    out |= (u64)buffer[0] << 40;

    return out;
}

u64
read_u64_be(u8* buffer) {
    u64 out = 0;

    out |= (u64)buffer[7];
    out |= (u64)buffer[6] << 8;
    out |= (u64)buffer[5] << 16;
    out |= (u64)buffer[4] << 24;
    out |= (u64)buffer[3] << 32;
    out |= (u64)buffer[2] << 40;
    out |= (u64)buffer[1] << 48;
    out |= (u64)buffer[0] << 56;

    return out;
}

u32
read_u24_be(u8* buffer) {
    u32 out = 0;

    out |= (u32)buffer[2];
    out |= (u32)buffer[1] << 8;
    out |= (u32)buffer[0] << 16;

    return out;
}

u32
read_u16_be(u8* buffer) {
    u32 out = 0;

    out |= (u32)buffer[1];
    out |= (u32)buffer[0] << 8;

    return out;
}

u64
buffer_to_u64(Buffer buffer) {
    u64 result = 0;

    u64 i = 0;
    while (i < buffer.len && buffer.ptr[i] == 0) {
        i++;
    }

    u64 end = (buffer.len - i) > 8 ? (i + 8) : buffer.len;
    for (; i < end; i++) {
        result <<= 8;
        result |= buffer.ptr[i];
    }

    return result;
}

void
print_error(void) {
    dprintf(STDERR_FILENO, "%s: %s\n", progname, strerror(errno));
}

bool
is_space(u8 c) {
    return (c == '\n' || c == '\v' || c == '\t' || c == '\r' || c == '\f' | c == ' ');
}

static u8
from_hex(u8 c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0xFF;
}

void
parse_hex(Buffer str, Buffer out, bool* err) {
    u64 len = str.len < out.len * 2 ? str.len : out.len * 2;
    ft_memset(out, 0);

    for (u64 i = 0; i < len; i += 2) {
        u8 hi = from_hex(str.ptr[i]);
        u8 lo = from_hex(i + 1 < len ? str.ptr[i + 1] : '0');

        if (hi == 0xFF || lo == 0xFF) {
            *err = true;
            return;
        }

        out.ptr[i / 2] = (hi << 4) | lo;
    }
}

void
print_hex(Buffer str) {
    for (u64 i = 0; i < str.len; i++) {
        dprintf(STDERR_FILENO, "%02X", str.ptr[i]);
    }
    dprintf(STDERR_FILENO, "\n");
}

bool
get_random_bytes(Buffer buffer) {
    int fd = open("/dev/random", O_RDONLY);
    if (fd < 0) return false;

    ssize_t bytes = read(fd, buffer.ptr, buffer.len);
    if (bytes < 0) {
        close(fd);
        return false;
    }

    return true;
}

bool
read_password(Buffer buffer, bool verify) {
    char verify_buf[MAX_PASSWORD_SIZE] = { 0 };
    u64 len = buffer.len > MAX_PASSWORD_SIZE ? MAX_PASSWORD_SIZE : buffer.len;

    const char* pass_ptr = readpassphrase("enter password: ", (char*)buffer.ptr, len, 0);

    const char* verify_ptr = 0;
    if (verify) verify_ptr = readpassphrase("reenter password: ", verify_buf, len, 0);

    if (!pass_ptr || (verify && !verify_ptr)) {
        dprintf(STDERR_FILENO, "%s: error reading password\n", progname);
        return false;
    }

    if (verify && !ft_memcmp(str(pass_ptr), str(verify_ptr))) {
        dprintf(STDERR_FILENO, "%s: passwords don't match\n", progname);
        return false;
    }

    return true;
}

int
get_infile_fd(const char* filename) {
    int fd = -1;
    if (filename) {
        fd = open(filename, O_RDONLY);
    } else {
        fd = STDIN_FILENO;
    }

    return fd;
}

int
get_outfile_fd(const char* filename) {
    int fd = -1;
    if (filename) {
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IROTH);
    } else {
        fd = STDOUT_FILENO;
    }

    return fd;
}

u64
power(u64 n, u64 k) {
    if (k == 0) return 1;

    while (k > 1) {
        n *= n;
        k--;
    }
    return n;
}

u64
power_mod(u64 x, u64 exp, u64 mod) {
    x %= mod;

    u64 result = 1;
    while (exp > 0) {
        if (exp & 1) result = (result * x) % mod;

        exp /= 2;
        x = (x * x) % mod;
    }

    return result;
}

bool
random_init(Random* random) {
    random->fd = open("/dev/urandom", O_RDONLY);

    return random->fd > 0;
}

void
random_deinit(Random* random) {
    assert(random->fd > 0);
    close(random->fd);
}

u64
random_number(Random* random, u64 min, u64 max) {
    assert(random->fd > 0);

    u64 num;
    ssize_t bytes = read(random->fd, &num, sizeof(num));
    if (bytes < 0) {
        dprintf(STDERR_FILENO, "%s: error getting random bytes\n", progname);
        arena_free(&arena);
        exit(EXIT_FAILURE);
    }

    num -= min;
    num %= max - min;
    num += min;

    return num;
}

static u64
extended_gcd(u64 a, u64 b, i64* x, i64* y) {
    i64 aa[2] = { 1, 0 };
    i64 bb[2] = { 0, 1 };
    i64 q;

    while (true) {
        q = a / b;
        a = a % b;

        aa[0] = aa[0] - q * aa[1];
        bb[0] = bb[0] - q * bb[1];

        if (a == 0) {
            *x = aa[1];
            *y = bb[1];
            return b;
        }

        q = b / a;
        b = b % a;

        aa[1] = aa[1] - q * aa[0];
        bb[1] = bb[1] - q * bb[0];

        if (b == 0) {
            *x = aa[0];
            *y = bb[0];
            return a;
        };
    }
}

u64
inverse_mod(u64 x, u64 y) {
    i64 a;
    i64 b;
    if (extended_gcd(x, y, &a, &b) != 1) {
        return 0;
    }

    if (a < 0) a += y;

    return a;
}
