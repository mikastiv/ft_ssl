#include "globals.h"
#include "types.h"
#include "utils.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

// https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Testing_against_small_sets_of_bases
static const u64 witnesses[] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41 };

static bool
miller_rabin_test(u64 n, u64 d, u64 a) {
    u64 x = power_mod(a, d, n);

    if (x == 1 || x == n - 1) return true;

    while (d != n - 1) {
        x = (x * x) % n;
        d *= 2;

        if (x == 1) return false;
        if (x == n - 1) return true;
    }

    return false;
}

bool
is_prime(u64 n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0) return false;

    u64 d = n - 1;
    while (d % 2 == 0) {
        d /= 2;
    }

    for (u64 i = 0; i < array_len(witnesses); i++) {
        if (!miller_rabin_test(n, d, witnesses[i])) {
            return false;
        }
    }

    return true;
}

bool
genrsa(void) {
    Random rng;
    if (!random_init(&rng)) {
        dprintf(STDERR_FILENO, "%s: failed to init rng\n", progname);
        return false;
    }

    u64 p = 0;
    u64 q = 0;
    while (true) {
        if (!p) p = random_number(&rng, 0, UINT32_MAX);
        if (!q) q = random_number(&rng, 0, UINT32_MAX);

        if (!is_prime(p)) p = 0;
        if (!is_prime(q)) q = 0;
        if (p == q) q = 0;

        if (p && q) break;
    }

    u64 n = p * q;
    u64 phi = (p - 1) * (q - 1);
    u64 e = 65537;
    u64 d = inverse_mod(e, phi);

    dprintf(STDERR_FILENO, "p: %" PRIu64 "\n", p);
    dprintf(STDERR_FILENO, "q: %" PRIu64 "\n", q);
    dprintf(STDERR_FILENO, "n: %" PRIu64 "\n", n);
    dprintf(STDERR_FILENO, "phi: %" PRIu64 "\n", phi);
    dprintf(STDERR_FILENO, "e: %" PRIu64 "\n", e);
    dprintf(STDERR_FILENO, "d: %" PRIu64 "\n", d);

    return true;
}
