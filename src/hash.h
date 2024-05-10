#pragma once

#include "types.h"

typedef struct {
    u32 state[4];
    u64 total_len;
    u8 buffer[64];
    u64 buffer_len;
} Md5;

Md5
md5_init(void);

void
md5_update(Md5* md5, Buffer buffer);

void
md5_final(Md5* md5, Buffer out);
