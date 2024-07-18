#include "types.h"
#include "utils.h"

#include <assert.h>

static bool
miller_rabin_test(Random* random, u64 n, u64 d) {
    u64 a = random_number(random, 2, n - 2);
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
is_prime(u64 n, f64 accuracy_percent) {
    assert(accuracy_percent <= 1.0);

    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0) return false;

    u64 k = accuracy_percent * (f64)64;
    u64 d = n - 1;
    while (d % 2 == 0) {
        d /= 2;
    }

    Random random;
    assert(random_init(&random));

    for (u64 i = 0; i < k; i++) {
        if (!miller_rabin_test(&random, n, d)) {
            random_deinit(&random);
            return false;
        }
    }

    random_deinit(&random);
    return true;
}
