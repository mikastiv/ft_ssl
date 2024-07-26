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
        dprintf(STDERR_FILENO, "+");
    }

    return true;
}

static u64
generate_prime(Random* rng, u64* first_prime) {
    u64 prime = 0;
    while (true) {
        prime = random_number(rng, 0x80000000, UINT32_MAX);
        dprintf(STDERR_FILENO, ".");

        if (first_prime && *first_prime == prime) continue;

        if (is_prime(prime)) break;
    }

    dprintf(STDERR_FILENO, "\n");

    return prime;
}

static void
output_private_key(u64 n, u64 e, u64 d, u64 p, u64 q, u64 exp1, u64 exp2, u64 coef, int fd) {
    AsnSeq ctx = asn_seq_init();

    AsnSeq private_key = asn_seq_init();
    asn_seq_add_integer(&private_key, 0, false); // version

    AsnSeq rsa = asn_seq_init();
    asn_seq_add_object_ident(&rsa, str(ASN_RSA_ENCRYPTION));
    asn_seq_add_null(&rsa, 0);

    asn_seq_add_seq(&private_key, &rsa);

    AsnSeq rsa_private_key = asn_seq_init();
    asn_seq_add_integer(&rsa_private_key, 0, false);    // version
    asn_seq_add_integer(&rsa_private_key, n, true);     // modulus
    asn_seq_add_integer(&rsa_private_key, e, false);    // public exponent
    asn_seq_add_integer(&rsa_private_key, d, false);    // private exponent
    asn_seq_add_integer(&rsa_private_key, p, true);     // prime 1
    asn_seq_add_integer(&rsa_private_key, q, true);     // prime 2
    asn_seq_add_integer(&rsa_private_key, exp1, false); // exponent 1
    asn_seq_add_integer(&rsa_private_key, exp2, false); // exponent 2
    asn_seq_add_integer(&rsa_private_key, coef, false); // coefficient

    asn_seq_add_octet_str_seq(&private_key, &rsa_private_key);
    asn_seq_add_seq(&ctx, &private_key);

    Buffer encoded = base64_encode(buf(ctx.buffer, ctx.len));

    Buffer begin = str("-----BEGIN RSA PRIVATE KEY-----\n");
    Buffer end = str("\n-----END RSA PRIVATE KEY-----\n");
    write(fd, begin.ptr, begin.len);
    write(fd, encoded.ptr, encoded.len);
    write(fd, end.ptr, end.len);
}

static void
output_public_key(u64 n, u64 e, int fd) {
    AsnSeq ctx = asn_seq_init();

    AsnSeq public_key = asn_seq_init();

    AsnSeq rsa = asn_seq_init();
    asn_seq_add_object_ident(&rsa, str(ASN_RSA_ENCRYPTION));
    asn_seq_add_null(&rsa, 0);

    asn_seq_add_seq(&public_key, &rsa);

    AsnSeq rsa_public_key = asn_seq_init();
    asn_seq_add_integer(&rsa_public_key, n, true);  // modulus
    asn_seq_add_integer(&rsa_public_key, e, false); // public exponent

    asn_seq_add_bit_str_seq(&public_key, &rsa_public_key);
    asn_seq_add_seq(&ctx, &public_key);

    // write(fd, ctx.buffer, ctx.len);

    Buffer encoded = base64_encode(buf(ctx.buffer, ctx.len));

    Buffer begin = str("-----BEGIN RSA PUBLIC KEY-----\n");
    Buffer end = str("\n-----END RSA PUBLIC KEY-----\n");
    write(fd, begin.ptr, begin.len);
    write(fd, encoded.ptr, encoded.len);
    write(fd, end.ptr, end.len);
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

    dprintf(STDERR_FILENO, "Generating RSA key with 64 bits\n");

    u64 p = generate_prime(&rng, 0);
    u64 q = generate_prime(&rng, &p);
    u64 n = p * q;
    u64 phi = (p - 1) * (q - 1);
    u64 e = 65537;
    u64 d = inverse_mod(e, phi);
    u64 exp1 = d % (p - 1);
    u64 exp2 = d % (q - 1);
    u64 coef = inverse_mod(q, p);

    dprintf(STDERR_FILENO, "e is %" PRIu64 " (%#" PRIx64 ")\n", e, e);

    output_private_key(n, e, d, p, q, exp1, exp2, coef, out_fd);
    output_public_key(n, e, STDOUT_FILENO);

    if (options->output_file && out_fd != -1) close(out_fd);
    return true;

genrsa_error:
    if (options->output_file && out_fd != -1) close(out_fd);
    return false;
}
