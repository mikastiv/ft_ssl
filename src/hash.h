#pragma once

#include "types.h"

typedef struct {
    u32 state[4];
    u64 total_len;
} Md5;

Md5
md5_init(void);

void
md5_update(Md5* md5, Buffer buffer);

void
md5_end(Md5* md5, Buffer out);
