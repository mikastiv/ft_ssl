#include "bignum.h"

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

BigNum
bignum_init(Buffer number) {
    assert(number.len <= BIGNUM_MAX_CHUNKS);

    BigNum out = { 0 };
    for (u64 i = number.len - 1, j = 0; j < number.len; i--, j++) {
        out.chunks[j] = number.ptr[i];
    }

    return out;
}

void
bignum_mul(BigNum* a, BigNum* b, BigNum* out) {
    *out = (BigNum){ 0 };

    for (u64 i = 0; i < BIGNUM_MAX_CHUNKS; i++) {
        u64 carry = 0;
        for (u64 j = 0; j < BIGNUM_MAX_CHUNKS; j++) {
            u64 a_part = a->chunks[i];
            u64 b_part = b->chunks[j];
            u64 c_part = out->chunks[i + j];

            u64 product = a_part * b_part + c_part + carry;
            out->chunks[i + j] = (BigNumChunk)product;
            carry = product >> (sizeof(BigNumChunk) * 8);
        }
    }
}

static i32
bignum_compare(BigNum* a, BigNum* b) {
    for (i64 i = BIGNUM_MAX_CHUNKS - 1; i >= 0; i--) {
        if (a->chunks[i] > b->chunks[i]) return 1;
        if (a->chunks[i] < b->chunks[i]) return -1;
    }

    return 0;
}

void
bignum_sub(BigNum* a, BigNum* b, BigNum* out) {
    *out = (BigNum){ 0 };

    u64 borrow = 0;
    for (u64 i = 0; i < BIGNUM_MAX_CHUNKS; i++) {
        u64 a_part = a->chunks[i];
        u64 b_part = b->chunks[i];

        u64 diff = a_part - b_part - borrow;
        borrow = (diff >> 63) & 1;
        if (borrow) {
            diff += 1 << (sizeof(BigNumChunk) * 8);
        }
        out->chunks[i] = (BigNumChunk)diff;
    }
}

void
bignum_mod(BigNum* a, BigNum* b, BigNum* out) {
    BigNum tmp_a = *a;
    BigNum tmp_b = *b;

    while (bignum_compare(&tmp_a, &tmp_b) >= 0) {
        BigNum tmp = { 0 };
        bignum_sub(&tmp_a, &tmp_b, &tmp);
        tmp_a = tmp;
    }

    *out = tmp_a;
}

void
bignum_print(BigNum* num) {
    u64 start = BIGNUM_MAX_CHUNKS - 1;
    while (start > 0 && num->chunks[start] == 0) start--;

    for (i64 i = start; i >= 0; i--) {
        dprintf(STDERR_FILENO, "%02X", num->chunks[i]);
    }
    dprintf(STDERR_FILENO, "\n");
}
