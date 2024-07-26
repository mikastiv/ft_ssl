#include "asn1.h"
#include "cipher.h"
#include "globals.h"
#include "standard.h"
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
        prime = random_number(rng, 0xC0000000, UINT32_MAX);
        dprintf(STDERR_FILENO, ".");

        if (first_prime && *first_prime == prime) continue;

        if (is_prime(prime)) break;
    }

    dprintf(STDERR_FILENO, "\n");

    return prime;
}

static Rsa
rsa_generate(Random* rng) {
    u64 p = generate_prime(rng, 0);
    u64 q = generate_prime(rng, &p);
    u64 n = p * q;
    u64 phi = (p - 1) * (q - 1);
    u64 e = 65537;
    u64 d = inverse_mod(e, phi);
    u64 exp1 = d % (p - 1);
    u64 exp2 = d % (q - 1);
    u64 coef = inverse_mod(q, p);

    return (Rsa){
        .prime1 = p,
        .prime2 = q,
        .modulus = n,
        .phi = phi,
        .pub_exponent = e,
        .priv_exponent = d,
        .exp1 = exp1,
        .exp2 = exp2,
        .coefficient = coef,
    };
}

static void
output_private_key(Rsa rsa, int fd) {
    AsnSeq ctx = asn_seq_init();

    AsnSeq private_key = asn_seq_init();
    asn_seq_add_integer(&private_key, 0, 32); // version

    AsnSeq rsa_algo = asn_seq_init();
    asn_seq_add_object_ident(&rsa_algo, str(ASN_RSA_ENCRYPTION));
    asn_seq_add_null(&rsa_algo, 0);

    asn_seq_add_seq(&private_key, &rsa_algo);

    AsnSeq rsa_private_key = asn_seq_init();
    asn_seq_add_integer(&rsa_private_key, 0, 32);
    asn_seq_add_integer(&rsa_private_key, rsa.modulus, 64);
    asn_seq_add_integer(&rsa_private_key, rsa.pub_exponent, 64);
    asn_seq_add_integer(&rsa_private_key, rsa.priv_exponent, 64);
    asn_seq_add_integer(&rsa_private_key, rsa.prime1, 32);
    asn_seq_add_integer(&rsa_private_key, rsa.prime2, 32);
    asn_seq_add_integer(&rsa_private_key, rsa.exp1, 32);
    asn_seq_add_integer(&rsa_private_key, rsa.exp2, 32);
    asn_seq_add_integer(&rsa_private_key, rsa.coefficient, 32);

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
output_public_key(Rsa rsa, int fd) {
    AsnSeq ctx = asn_seq_init();

    AsnSeq public_key = asn_seq_init();

    AsnSeq rsa_algo = asn_seq_init();
    asn_seq_add_object_ident(&rsa_algo, str(ASN_RSA_ENCRYPTION));
    asn_seq_add_null(&rsa_algo, 0);

    asn_seq_add_seq(&public_key, &rsa_algo);

    AsnSeq rsa_public_key = asn_seq_init();
    asn_seq_add_integer(&rsa_public_key, rsa.modulus, 64);
    asn_seq_add_integer(&rsa_public_key, rsa.pub_exponent, 64);

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

typedef enum {
    PemNone,
    PemPublic,
    PemRsaPublic,
    PemPrivate,
    PemRsaPrivate,
    PemEncPrivate,
} PemKeyType;

static const char* public_key_begin = "-----BEGIN PUBLIC KEY-----\n";
static const char* public_key_end = "-----END PUBLIC KEY-----\n";
static const char* public_key_begin_rsa = "-----BEGIN RSA PUBLIC KEY-----\n";
static const char* public_key_end_rsa = "-----END RSA PUBLIC KEY-----\n";
static const char* private_key_begin = "-----BEGIN PRIVATE KEY-----\n";
static const char* private_key_end = "-----END PRIVATE KEY-----\n";
static const char* private_key_begin_rsa = "-----BEGIN RSA PRIVATE KEY-----\n";
static const char* private_key_end_rsa = "-----END RSA PRIVATE KEY-----\n";
static const char* private_key_begin_enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
static const char* private_key_end_enc = "-----END ENCRYPTED PRIVATE KEY-----\n";

static Buffer
read_pem_key(Buffer input, Buffer begin, Buffer end) {
    Buffer begin_delim = ft_strstr(input, begin);

    if (!begin_delim.ptr) {
        return (Buffer){ 0 };
    }

    Buffer end_delim = ft_strstr(input, end);
    if (!end_delim.ptr) {
        return (Buffer){ 0 };
    }

    if (begin_delim.ptr >= end_delim.ptr) {
        return (Buffer){ 0 };
    }

    u8* start_ptr = begin_delim.ptr + begin_delim.len;
    Buffer data = buf(start_ptr, end_delim.ptr - start_ptr);

    return data;
}

static Buffer
read_private_key(Buffer input, PemKeyType* out) {
    *out = PemPrivate;
    Buffer base64_key = read_pem_key(input, str(private_key_begin), str(private_key_end));

    if (!base64_key.ptr) {
        *out = PemRsaPrivate;
        base64_key = read_pem_key(input, str(private_key_begin_rsa), str(private_key_end_rsa));
    }

    if (!base64_key.ptr) {
        *out = PemEncPrivate;
        base64_key = read_pem_key(input, str(private_key_begin_enc), str(private_key_end_enc));
    }

    if (!base64_key.ptr) {
        *out = PemNone;
    }

    return base64_key;
}

static Buffer
read_public_key(Buffer input, PemKeyType* out) {
    *out = PemPublic;
    Buffer base64_key = read_pem_key(input, str(public_key_begin), str(public_key_end));

    if (!base64_key.ptr) {
        *out = PemRsaPublic;
        base64_key = read_pem_key(input, str(public_key_begin_rsa), str(public_key_end_rsa));
    }

    if (!base64_key.ptr) {
        *out = PemNone;
    }

    return base64_key;
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

    Rsa rsa = rsa_generate(&rng);

    dprintf(STDERR_FILENO, "e is %" PRIu64 " (%#" PRIx64 ")\n", rsa.pub_exponent, rsa.pub_exponent);

    output_private_key(rsa, out_fd);
    output_public_key(rsa, STDOUT_FILENO);

    if (options->output_file && out_fd != -1) close(out_fd);
    return true;

genrsa_error:
    if (options->output_file && out_fd != -1) close(out_fd);
    return false;
}

bool
rsa(RsaOptions* options) {
    int in_fd = get_infile_fd(options->input_file);
    if (in_fd < 0) {
        print_error();
        goto rsa_err;
    }

    Buffer input = read_all_fd(in_fd, get_filesize(in_fd));

    PemKeyType key_type = PemNone;
    Buffer base64_key = { 0 };
    if (options->public_key_in) {
        base64_key = read_public_key(input, &key_type);
    } else {
        base64_key = read_private_key(input, &key_type);
    }

    if (!base64_key.ptr) {
        dprintf(
            STDERR_FILENO,
            "%s: could not read %s key from %s\n",
            progname,
            options->public_key_in ? "public" : "private",
            in_fd == STDIN_FILENO ? "<stdin>" : options->input_file
        );
        goto rsa_err;
    }

    dprintf(STDERR_FILENO, "Type: %d\n", key_type);
    write(STDERR_FILENO, base64_key.ptr, base64_key.len);

    Buffer decoded = base64_decode(base64_key);
    if (!decoded.ptr) {
        dprintf(STDERR_FILENO, "%s: invalid base64 input\n", progname);
        goto rsa_err;
    }

    if (options->input_file && in_fd != -1) close(in_fd);
    return true;

rsa_err:
    if (options->input_file && in_fd != -1) close(in_fd);
    return false;
}
