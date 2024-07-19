#include "bignum.h"

#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <unistd.h>

BigNum
bignum_init(u64 bitsize) {
    assert(bitsize <= BIGNUM_MAX_BITS);
    assert(bitsize % sizeof(u32) == 0);

    const u64 chunk_count = bitsize / (sizeof(u32) * 8);
    assert(chunk_count * 2 <= BIGNUM_MAX_CHUNKS);

    return (BigNum){ .chunk_count = chunk_count };
}

void
bignum_mul(BigNum* a, BigNum* b, BigNum* out) {
    ft_memset(buf((u8*)out->chunks, sizeof(out->chunks)), 0);

    if (a->chunk_count < b->chunk_count) {
        BigNum* tmp = a;
        a = b;
        b = tmp;
    }

    u64 extra_chunks = 0;
    for (u64 i = 0; i < a->chunk_count; i++) {
        u64 carry = 0;
        for (u64 j = 0; j < b->chunk_count; j++) {
            u64 product = (u64)a->chunks[i] * (u64)b->chunks[j] + (u64)out->chunks[i + j] + carry;
            out->chunks[i + j] = (u32)product;
            carry = product >> 32;
        }
        if (carry) {
            u64 index = i + out->chunk_count;
            assert(index < BIGNUM_MAX_CHUNKS);

            out->chunks[index] = carry;
            if (index >= a->chunk_count) {
                extra_chunks++;
            }
        }
    }

    out->chunk_count = a->chunk_count + extra_chunks;
}

void
bignum_print(BigNum* num) {
    for (i64 i = num->chunk_count - 1; i >= 0; i--) {
        dprintf(STDERR_FILENO, "%08X", num->chunks[i]);
    }
    dprintf(STDERR_FILENO, "\n");
}
