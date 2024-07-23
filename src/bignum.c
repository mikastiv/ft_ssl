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

// void
// bignum_mul(BigNum* a, BigNum* b, BigNum* out) {
//     ft_memset(buf((u8*)out->chunks, sizeof(out->chunks)), 0);

//     if (a->chunk_count < b->chunk_count) {
//         swap(&a, &b);
//     }

//     u64 extra_chunks = 0;
//     for (u64 i = 0; i < a->chunk_count; i++) {
//         u64 carry = 0;
//         for (u64 j = 0; j < b->chunk_count; j++) {
//             u64 product = (u64)a->chunks[i] * (u64)b->chunks[j] + (u64)out->chunks[i + j] +
//             carry; out->chunks[i + j] = (BigNumChunk)product; carry = product >>
//             (sizeof(BigNumChunk) * 8);
//         }
//         if (carry) {
//             u64 index = i + out->chunk_count;
//             assert(index < BIGNUM_MAX_CHUNKS);

//             out->chunks[index] = carry;
//             if (index >= a->chunk_count) {
//                 extra_chunks++;
//             }
//         }
//     }

//     out->chunk_count = a->chunk_count + extra_chunks;
// }

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
        if (borrow) {
            diff += 1 << (sizeof(BigNumChunk) * 8);
        }
        out->chunks[i] = (BigNumChunk)diff;

        borrow = (diff >> 63) & 1;
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
