#pragma once

#include "types.h"

#define BIGNUM_MAX_BITS 4096
#define BIGNUM_MAX_CHUNKS (BIGNUM_MAX_BITS / (sizeof(u32) * 8))

typedef struct {
    u32 chunks[BIGNUM_MAX_CHUNKS];
    u64 chunk_count;
} BigNum;

BigNum
bignum_init(u64 bitsize);

void
bignum_mul(BigNum* a, BigNum* b, BigNum* out);

void
bignum_mod(BigNum* a, BigNum* b, BigNum* out);

void
bignum_powermod(BigNum* a, BigNum* b, BigNum* out);

void
bignum_print(BigNum* num);
