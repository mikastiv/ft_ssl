#pragma once

#include "types.h"

typedef u8 BigNumChunk;

#define BIGNUM_MAX_BITS 4096
#define BIGNUM_MAX_CHUNKS (BIGNUM_MAX_BITS / (sizeof(BigNumChunk) * 8))
#define BIGNUM_CHUNK_BITS (sizeof(BigNumChunk) * 8)

typedef struct {
    BigNumChunk chunks[BIGNUM_MAX_CHUNKS];
} BigNum;

BigNum
bignum_init(Buffer number);

void
bignum_sub(BigNum* a, BigNum* b, BigNum* out);

void
bignum_mul(BigNum* a, BigNum* b, BigNum* out);

void
bignum_div(BigNum* a, BigNum* b, BigNum* quotient, BigNum* remainder);

void
bignum_mod(BigNum* a, BigNum* b, BigNum* out);

void
bignum_powermod(BigNum* a, BigNum* b, BigNum* out);

void
bignum_print(BigNum* num);
