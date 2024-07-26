#include "asn1.h"
#include "cipher.h"
#include "globals.h"
#include "types.h"
#include "utils.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include <fcntl.h>
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

static bool
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
genrsa(GenRsaOptions* options) {
    int out_fd = get_outfile_fd(options->output_file);
    if (out_fd == -1) {
        print_error();
        goto genrsa_error;
    }

    Random rng;
    if (!random_init(&rng)) {
        dprintf(STDERR_FILENO, "%s: failed to init rng\n", progname);
        return false;
    }

    u64 p = 0;
    u64 q = 0;
    while (true) {
        if (!p) p = random_number(&rng, 0xC0000000, UINT32_MAX);
        if (!q) q = random_number(&rng, 0xC0000000, UINT32_MAX);

        if (!is_prime(p)) p = 0;
        if (!is_prime(q)) q = 0;
        if (p == q) q = 0;

        if (p && q) break;
    }

    u64 n = p * q;
    u64 phi = (p - 1) * (q - 1);
    u64 e = 65537;
    u64 d = inverse_mod(e, phi);
    u64 exp1 = d % (p - 1);
    u64 exp2 = d % (q - 1);
    u64 coef = inverse_mod(q, p);

    AsnSeq ctx = asn_seq_init();

    AsnSeq private_key = asn_seq_init();
    asn_seq_add_integer(&private_key, 0); // version

    AsnSeq rsa = asn_seq_init();
    asn_seq_add_object_ident(&rsa, str(ASN_RSA_ENCRYPTION));
    asn_seq_add_null(&rsa, 0);

    asn_seq_add_seq(&private_key, &rsa);

    AsnSeq rsa_private_key = asn_seq_init();
    asn_seq_add_integer(&rsa_private_key, 0);    // version
    asn_seq_add_integer(&rsa_private_key, n);    // modulus
    asn_seq_add_integer(&rsa_private_key, e);    // public exponent
    asn_seq_add_integer(&rsa_private_key, d);    // private exponent
    asn_seq_add_integer(&rsa_private_key, p);    // prime 1
    asn_seq_add_integer(&rsa_private_key, q);    // prime 2
    asn_seq_add_integer(&rsa_private_key, exp1); // exponent 1
    asn_seq_add_integer(&rsa_private_key, exp2); // exponent 2
    asn_seq_add_integer(&rsa_private_key, coef); // coefficient

    asn_seq_add_octet_str_seq(&private_key, &rsa_private_key);
    asn_seq_add_seq(&ctx, &private_key);

    Buffer encoded = base64_encode(buf(ctx.buffer, ctx.len));

    Buffer begin = str("-----BEGIN RSA PRIVATE KEY-----\n");
    Buffer end = str("\n-----END RSA PRIVATE KEY-----\n");
    write(out_fd, begin.ptr, begin.len);
    write(out_fd, encoded.ptr, encoded.len);
    write(out_fd, end.ptr, end.len);

    if (options->output_file && out_fd != -1) close(out_fd);
    return true;

genrsa_error:
    if (options->output_file && out_fd != -1) close(out_fd);
    return false;
}
