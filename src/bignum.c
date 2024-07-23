#include "bignum.h"

#include "utils.h"

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
            carry = product >> BIGNUM_CHUNK_BITS;
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

static void
bignum_shift_right(BigNum* a, u32 bits) {
    u32 word_shift = bits / BIGNUM_CHUNK_BITS;
    u32 bit_shift = bits % BIGNUM_CHUNK_BITS;

    if (word_shift) {
        for (u64 i = 0; i < BIGNUM_MAX_CHUNKS - word_shift; i++) {
            a->chunks[i] = a->chunks[i + word_shift];
        }
        for (u64 i = BIGNUM_MAX_CHUNKS - word_shift; i < BIGNUM_MAX_CHUNKS; i++) {
            a->chunks[i] = 0;
        }
    }

    if (bit_shift) {
        u64 carry = 0;
        for (i64 i = BIGNUM_MAX_CHUNKS - 1; i >= 0; i--) {
            u64 temp = a->chunks[i];
            a->chunks[i] = (temp >> bit_shift) | carry;
            carry = temp << (BIGNUM_CHUNK_BITS - bit_shift);
        }
    }
}

static void
bignum_shift_left(BigNum* a, u32 bits) {
    u32 word_shift = bits / BIGNUM_CHUNK_BITS;
    u32 bit_shift = bits % BIGNUM_CHUNK_BITS;

    if (word_shift) {
        for (i64 i = BIGNUM_MAX_CHUNKS - 1; i >= word_shift; i--) {
            a->chunks[i] = a->chunks[i - word_shift];
        }
        for (u64 i = 0; i < word_shift; i++) {
            a->chunks[i] = 0;
        }
    }

    if (bit_shift) {
        u64 carry = 0;
        for (u64 i = 0; i < BIGNUM_MAX_CHUNKS; i++) {
            u64 temp = a->chunks[i];
            a->chunks[i] = (temp << bit_shift) | carry;
            carry = temp >> (BIGNUM_CHUNK_BITS - bit_shift);
        }
    }
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
            diff += 1 << BIGNUM_CHUNK_BITS;
        }
        out->chunks[i] = (BigNumChunk)diff;
    }
}

void
bignum_mod(BigNum* a, BigNum* b, BigNum* out) {
    u32 k = BIGNUM_MAX_BITS / 2;

    BigNum q1 = { 0 };
    ft_memcpy(
        buf(q1.chunks + BIGNUM_MAX_CHUNKS / 2, sizeof(BigNumChunk) * (BIGNUM_MAX_CHUNKS / 2)),
        buf(a->chunks + BIGNUM_MAX_CHUNKS / 2, sizeof(BigNumChunk) * (BIGNUM_MAX_CHUNKS / 2))
    );

    BigNum q2 = { 0 };
    bignum_mul(&q2, &q1, mu);

    BigNum q3 = { 0 };
    bignum_shift_right(&q2, k / 2);

    BigNum r1 = { 0 };
    ft_memcpy(
        buf(r1.chunks, sizeof(BigNumChunk) * BIGNUM_MAX_CHUNKS),
        buf(a->chunks, sizeof(BigNumChunk) * BIGNUM_MAX_CHUNKS)
    );

    BigNum r2 = { 0 };
    BigNum q3m = { 0 };
    bignum_mul(&q3m, &q3, b);
    bignum_sub(&r2, &r1, &q3m);

    while (bignum_compare(&r2, b) >= 0) {
        BigNum temp = { 0 };
        bignum_sub(&temp, &r2, b);
        r2 = temp;
    }

    *out = r2;
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
