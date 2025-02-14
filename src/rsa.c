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

static Rsa64
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

    return (Rsa64){
        .prime1 = p,
        .prime2 = q,
        .modulus = n,
        .pub_exponent = e,
        .priv_exponent = d,
        .exp1 = exp1,
        .exp2 = exp2,
        .coefficient = coef,
    };
}

static const char* public_key_begin = "-----BEGIN PUBLIC KEY-----\n";
static const char* public_key_end = "\n-----END PUBLIC KEY-----\n";
static const char* private_key_begin = "-----BEGIN PRIVATE KEY-----\n";
static const char* private_key_end = "\n-----END PRIVATE KEY-----\n";
static const char* private_key_begin_rsa = "-----BEGIN RSA PRIVATE KEY-----\n";
static const char* private_key_end_rsa = "\n-----END RSA PRIVATE KEY-----\n";
static const char* private_key_begin_enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
static const char* private_key_end_enc = "\n-----END ENCRYPTED PRIVATE KEY-----\n";

static AsnSeq
create_private_key(Rsa64 rsa) {
    AsnSeq ctx = asn_seq_init();

    AsnSeq private_key = asn_seq_init();
    asn_seq_add_integer(&private_key, 0); // version

    AsnSeq rsa_algo = asn_seq_init();
    asn_seq_add_object_ident(&rsa_algo, str(ASN_RSA_ENCRYPTION));
    asn_seq_add_null(&rsa_algo, 0);

    asn_seq_add_seq(&private_key, &rsa_algo);

    AsnSeq rsa_private_key = asn_seq_init();
    asn_seq_add_integer(&rsa_private_key, 0);
    asn_seq_add_integer(&rsa_private_key, rsa.modulus);
    asn_seq_add_integer(&rsa_private_key, rsa.pub_exponent);
    asn_seq_add_integer(&rsa_private_key, rsa.priv_exponent);
    asn_seq_add_integer(&rsa_private_key, rsa.prime1);
    asn_seq_add_integer(&rsa_private_key, rsa.prime2);
    asn_seq_add_integer(&rsa_private_key, rsa.exp1);
    asn_seq_add_integer(&rsa_private_key, rsa.exp2);
    asn_seq_add_integer(&rsa_private_key, rsa.coefficient);

    asn_seq_add_octet_str_seq(&private_key, &rsa_private_key);
    asn_seq_add_seq(&ctx, &private_key);

    return ctx;
}

static void
output_private_key(Rsa64 rsa, int fd) {
    AsnSeq ctx = create_private_key(rsa);
    Buffer encoded = base64_encode(buf(ctx.buffer, ctx.len));

    Buffer begin = str(private_key_begin);
    Buffer end = str(private_key_end);
    (void)write(fd, begin.ptr, begin.len);
    (void)write(fd, encoded.ptr, encoded.len);
    (void)write(fd, end.ptr, end.len);
}

static void
output_public_key(Rsa64 rsa, int fd) {
    AsnSeq ctx = asn_seq_init();

    AsnSeq public_key = asn_seq_init();

    AsnSeq rsa_algo = asn_seq_init();
    asn_seq_add_object_ident(&rsa_algo, str(ASN_RSA_ENCRYPTION));
    asn_seq_add_null(&rsa_algo, 0);

    asn_seq_add_seq(&public_key, &rsa_algo);

    AsnSeq rsa_public_key = asn_seq_init();
    asn_seq_add_integer(&rsa_public_key, rsa.modulus);
    asn_seq_add_integer(&rsa_public_key, rsa.pub_exponent);

    asn_seq_add_bit_str_seq(&public_key, &rsa_public_key);
    asn_seq_add_seq(&ctx, &public_key);

    Buffer encoded = base64_encode(buf(ctx.buffer, ctx.len));

    Buffer begin = str(public_key_begin);
    Buffer end = str(public_key_end);
    (void)write(fd, begin.ptr, begin.len);
    (void)write(fd, encoded.ptr, encoded.len);
    (void)write(fd, end.ptr, end.len);
}

typedef enum {
    EncryptionDes,
    EncryptionDesEde3,
} EncryptionAlgo;

static void
output_encoded_private_key(Rsa64 rsa, int fd, const char* password, Buffer salt, EncryptionAlgo algo) {
    assert(salt.len == PBKDF2_SALT_SIZE);

    u8 key[PBKDF2_MAX_KEY_SIZE + DES_BLOCK_SIZE] = { 0 };
    u8 iv[DES_BLOCK_SIZE] = { 0 };
    u64 keylen = DES_KEY_SIZE;
    u64 ivlen = DES_BLOCK_SIZE;
    u64 iterations = 2048;
    Buffer algo_ident = str(ASN_DES_CBC);

    switch (algo) {
        case EncryptionDes: {
            keylen = DES_KEY_SIZE;
            algo_ident = str(ASN_DES_CBC);
        } break;
        case EncryptionDesEde3: {
            keylen = DES_KEY_SIZE * 3;
            algo_ident = str(ASN_DES_EDE3_CBC);
        } break;
        default:
            dprintf(STDERR_FILENO, "%s: unknown encryption algo\n", progname);
            return;
    }

    Des64 des_iv;
    pbkdf2_generate(str(password), salt, iterations, buf(key, keylen + ivlen));
    ft_memcpy(buf(iv, ivlen), buf(key + keylen, ivlen));
    ft_memcpy(buf(des_iv.block, ivlen), buf(iv, ivlen));

    AsnSeq ctx = create_private_key(rsa);

    AsnSeq enc_ctx = asn_seq_init();

    AsnSeq enc_key = asn_seq_init();

    AsnSeq enc_algo = asn_seq_init();
    asn_seq_add_object_ident(&enc_algo, str(ASN_PKCS5_PBES2));

    AsnSeq algo_params = asn_seq_init();

    AsnSeq algo_params_seq = asn_seq_init();
    asn_seq_add_object_ident(&algo_params_seq, str(ASN_PKCS5_PBKF2));

    AsnSeq pbkdf2_params = asn_seq_init();
    asn_seq_add_octet_str(&pbkdf2_params, salt);
    asn_seq_add_integer(&pbkdf2_params, iterations);

    AsnSeq hmac = asn_seq_init();
    asn_seq_add_object_ident(&hmac, str(ASN_HMAC_SHA256));
    asn_seq_add_null(&hmac, 0);

    asn_seq_add_seq(&pbkdf2_params, &hmac);

    asn_seq_add_seq(&algo_params_seq, &pbkdf2_params);

    asn_seq_add_seq(&algo_params, &algo_params_seq);

    AsnSeq rsa_algo = asn_seq_init();
    asn_seq_add_object_ident(&rsa_algo, algo_ident);
    asn_seq_add_octet_str(&rsa_algo, buf(iv, ivlen));

    asn_seq_add_seq(&algo_params, &rsa_algo);

    asn_seq_add_seq(&enc_algo, &algo_params);

    asn_seq_add_seq(&enc_key, &enc_algo);

    Buffer des;
    switch (algo) {
        case EncryptionDes:
            des = des_cbc_encrypt(buf(ctx.buffer, ctx.len), buf(key, keylen), des_iv);
            break;
        case EncryptionDesEde3:
            des = des3_cbc_encrypt(buf(ctx.buffer, ctx.len), buf(key, keylen), des_iv);
            break;
    }

    asn_seq_add_octet_str(&enc_key, des);

    asn_seq_add_seq(&enc_ctx, &enc_key);

    Buffer encoded = base64_encode(buf(enc_ctx.buffer, enc_ctx.len));

    Buffer begin = str(private_key_begin_enc);
    Buffer end = str(private_key_end_enc);
    (void)write(fd, begin.ptr, begin.len);
    (void)write(fd, encoded.ptr, encoded.len);
    (void)write(fd, end.ptr, end.len);
}

typedef enum {
    PemNone,
    PemPublic,
    PemRsaPublic,
    PemPrivate,
    PemRsaPrivate,
    PemEncPrivate,
} PemKeyType;

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
        *out = PemNone;
    }

    return base64_key;
}

static bool
decode_private_key(Buffer input, Rsa* rsa) {
    AsnParser parser = { .data = input, .valid = true };

    AsnEntry main_seq = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, 0, AsnSequence, &main_seq)) return false;

    AsnEntry version = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_seq_first_entry(main_seq), AsnInteger, &version)) return false;

    {
        u64 version_u64 = 0;
        if (!asn_integer_to_u64(version.data, &version_u64)) return false;
        if (version_u64 != 0) return false;
    }

    AsnEntry key_algo = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(version), AsnSequence, &key_algo)) return false;

    {
        AsnEntry algo_identifier = { 0 };
        if (!asn_next_entry_and_is_tag(&parser, asn_seq_first_entry(key_algo), AsnObjectIdentifier, &algo_identifier))
            return false;
        if (!ft_memcmp(algo_identifier.data, str(ASN_RSA_ENCRYPTION))) return false;

        AsnEntry algo_params = { 0 };
        if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(algo_identifier), AsnNull, &algo_params))
            return false;
        if (algo_params.data.len != 0) return false;
    }

    AsnEntry private_key = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(key_algo), AsnOctetString, &private_key)) return true;

    AsnEntry key_data_sequence = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_seq_first_entry(private_key), AsnSequence, &key_data_sequence))
        return false;

    AsnEntry key_version = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_seq_first_entry(key_data_sequence), AsnInteger, &key_version))
        return false;

    {
        u64 key_version_u64 = 0;
        if (!asn_integer_to_u64(key_version.data, &key_version_u64)) return false;
        if (key_version_u64 != 0) return false; // version 0 only
    }

    AsnEntry modulus = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(key_version), AsnInteger, &modulus)) return false;

    AsnEntry e = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(modulus), AsnInteger, &e)) return false;

    AsnEntry d = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(e), AsnInteger, &d)) return false;

    AsnEntry p = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(d), AsnInteger, &p)) return false;

    AsnEntry q = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(p), AsnInteger, &q)) return false;

    AsnEntry exp1 = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(q), AsnInteger, &exp1)) return false;

    AsnEntry exp2 = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(exp1), AsnInteger, &exp2)) return false;

    AsnEntry coef = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(exp2), AsnInteger, &coef)) return false;

    *rsa = (Rsa){
        .modulus = modulus.data,
        .pub_exponent = e.data,
        .priv_exponent = d.data,
        .prime1 = p.data,
        .prime2 = q.data,
        .exp1 = exp1.data,
        .exp2 = exp2.data,
        .coefficient = coef.data,
        .private_key = true,
    };

    return true;
}

static bool
decode_private_rsa_key(Buffer input, Rsa* rsa) {
    AsnParser parser = { .data = input, .valid = true };

    AsnEntry main_seq = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, 0, AsnSequence, &main_seq)) return false;

    AsnEntry version = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_seq_first_entry(main_seq), AsnInteger, &version)) return false;

    AsnEntry modulus = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(version), AsnInteger, &modulus)) return false;

    AsnEntry e = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(modulus), AsnInteger, &e)) return false;

    AsnEntry d = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(e), AsnInteger, &d)) return false;

    AsnEntry p = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(d), AsnInteger, &p)) return false;

    AsnEntry q = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(p), AsnInteger, &q)) return false;

    AsnEntry exp1 = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(q), AsnInteger, &exp1)) return false;

    AsnEntry exp2 = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(exp1), AsnInteger, &exp2)) return false;

    AsnEntry coef = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(exp2), AsnInteger, &coef)) return false;

    *rsa = (Rsa){
        .modulus = modulus.data,
        .pub_exponent = e.data,
        .priv_exponent = d.data,
        .prime1 = p.data,
        .prime2 = q.data,
        .exp1 = exp1.data,
        .exp2 = exp2.data,
        .coefficient = coef.data,
        .private_key = true,
    };

    return true;
}

static bool
decode_public_key(Buffer input, Rsa* rsa) {
    AsnParser parser = { .data = input, .valid = true };

    AsnEntry main_seq = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, 0, AsnSequence, &main_seq)) return false;

    AsnEntry key_algo = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_seq_first_entry(main_seq), AsnSequence, &key_algo)) return false;

    {
        AsnEntry algo_identifier = { 0 };
        if (!asn_next_entry_and_is_tag(&parser, asn_seq_first_entry(key_algo), AsnObjectIdentifier, &algo_identifier))
            return false;

        if (!ft_memcmp(algo_identifier.data, str(ASN_RSA_ENCRYPTION))) return false;

        AsnEntry algo_params = { 0 };
        if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(algo_identifier), AsnNull, &algo_params))
            return false;
        if (algo_params.data.len != 0) return false;
    }

    AsnEntry public_key = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(key_algo), AsnBitString, &public_key)) return false;

    u64 bitstring_start = asn_seq_first_entry(public_key);
    u8 unused_bits = input.ptr[bitstring_start++];
    assert(unused_bits == 0);
    (void)unused_bits;

    AsnEntry key_data_sequence = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, bitstring_start, AsnSequence, &key_data_sequence)) return false;

    AsnEntry modulus = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_seq_first_entry(key_data_sequence), AsnInteger, &modulus)) return false;

    AsnEntry e = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(modulus), AsnInteger, &e)) return false;

    *rsa = (Rsa){
        .modulus = modulus.data,
        .pub_exponent = e.data,
        .private_key = false,
    };

    return true;
}

typedef struct {
    Buffer pbkdf2_salt;
    u64 pbkdf2_iterations;
    EncryptionAlgo algo;
    Buffer iv;
    Buffer encrypted_data;
} EncryptedKey;

static bool
decode_encrypted_private_key(Buffer input, EncryptedKey* out) {
    AsnParser parser = { .data = input, .valid = true };

    AsnEntry main_seq = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, 0, AsnSequence, &main_seq)) return false;

    AsnEntry encryption_algo_seq = { 0 };
    if (!asn_next_entry_and_is_tag(&parser, asn_seq_first_entry(main_seq), AsnSequence, &encryption_algo_seq))
        return false;

    AsnEntry pbkdf2_salt = { 0 };
    AsnEntry pbkdf2_iterations = { 0 };
    AsnEntry encryption_identifier = { 0 };
    AsnEntry encryption_iv = { 0 };
    EncryptionAlgo algo = EncryptionDes;
    {
        AsnEntry algo_identifier = { 0 };
        if (!asn_next_entry_and_is_tag(
                &parser,
                asn_seq_first_entry(encryption_algo_seq),
                AsnObjectIdentifier,
                &algo_identifier
            ))
            return false;
        if (!ft_memcmp(algo_identifier.data, str(ASN_PKCS5_PBES2))) return false;

        AsnEntry algo_params = { 0 };
        if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(algo_identifier), AsnSequence, &algo_params))
            return false;

        AsnEntry algo_param_seq = { 0 };
        if (!asn_next_entry_and_is_tag(&parser, asn_seq_first_entry(algo_params), AsnSequence, &algo_param_seq))
            return false;
        {

            AsnEntry pbkdf2 = { 0 };
            if (!asn_next_entry_and_is_tag(&parser, asn_seq_first_entry(algo_param_seq), AsnObjectIdentifier, &pbkdf2))
                return false;
            if (!ft_memcmp(pbkdf2.data, str(ASN_PKCS5_PBKF2))) return false;

            AsnEntry pbkdf2_params = { 0 };
            if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(pbkdf2), AsnSequence, &pbkdf2_params))
                return false;

            if (!asn_next_entry_and_is_tag(&parser, asn_seq_first_entry(pbkdf2_params), AsnOctetString, &pbkdf2_salt))
                return false;

            if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(pbkdf2_salt), AsnInteger, &pbkdf2_iterations))
                return false;

            AsnEntry hmac_algo = { 0 };
            if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(pbkdf2_iterations), AsnSequence, &hmac_algo))
                return false;

            AsnEntry hmac_identifier = { 0 };
            if (!asn_next_entry_and_is_tag(
                    &parser,
                    asn_seq_first_entry(hmac_algo),
                    AsnObjectIdentifier,
                    &hmac_identifier
                ))
                return false;
            if (!ft_memcmp(hmac_identifier.data, str(ASN_HMAC_SHA256))) return false;

            AsnEntry hmac_null = { 0 };
            if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(hmac_identifier), AsnNull, &hmac_null))
                return false;
        }

        AsnEntry encryption_algo = { 0 };
        if (!asn_next_entry_and_is_tag(&parser, asn_next_entry_offset(algo_param_seq), AsnSequence, &encryption_algo))
            return false;

        if (!asn_next_entry_and_is_tag(
                &parser,
                asn_seq_first_entry(encryption_algo),
                AsnObjectIdentifier,
                &encryption_identifier
            ))
            return false;
        if (ft_memcmp(encryption_identifier.data, str(ASN_DES_CBC))) {
            algo = EncryptionDes;
        } else if (ft_memcmp(encryption_identifier.data, str(ASN_DES_EDE3_CBC))) {
            algo = EncryptionDesEde3;
        } else {
            return false;
        }

        if (!asn_next_entry_and_is_tag(
                &parser,
                asn_next_entry_offset(encryption_identifier),
                AsnOctetString,
                &encryption_iv
            ))
            return false;
    }

    AsnEntry encrypted_data = { 0 };
    if (!asn_next_entry_and_is_tag(
            &parser,
            asn_next_entry_offset(encryption_algo_seq),
            AsnOctetString,
            &encrypted_data
        ))
        return false;

    *out = (EncryptedKey){
        .pbkdf2_salt = pbkdf2_salt.data,
        .pbkdf2_iterations = buffer_to_u64(pbkdf2_iterations.data),
        .algo = algo,
        .iv = encryption_iv.data,
        .encrypted_data = encrypted_data.data,
    };

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

    dprintf(STDERR_FILENO, "Generating RSA key with 64 bits\n");

    Rsa64 rsa = rsa_generate(&rng);

    dprintf(STDERR_FILENO, "e is %" PRIu64 " (%#" PRIx64 ")\n", rsa.pub_exponent, rsa.pub_exponent);

    output_private_key(rsa, out_fd);

    if (options->output_file && out_fd != -1) close(out_fd);
    return true;

genrsa_error:
    if (options->output_file && out_fd != -1) close(out_fd);
    return false;
}

static bool
number_too_big(Buffer bigint) {
    i64 index = bigint.len > 0 ? (i64)bigint.len - 1 : 0;
    u8 bytes = 0;

    while (index >= 0) {
        if (bytes >= sizeof(u64)) {
            return true;
        }

        index--;
        bytes++;
    }

    return false;
}

static void
print_bigint_dec(int fd, Buffer bigint) {
    assert((bigint.len & 0x8000000000000000) == 0);

    i64 index = 0;
    u64 value = 0;

    assert(!number_too_big(bigint));

    while (index < (i64)bigint.len) {
        value *= 256;
        value += bigint.ptr[index];
        index++;
    }

    u8 buffer[512];
    index = 0;
    while (value > 0) {
        buffer[index++] = value % 10;
        value /= 10;
    }
    while (index > 0) {
        index--;
        dprintf(fd, "%u", buffer[index]);
    };
}

static void
print_bigint_hex(int fd, Buffer bigint, bool text_out) {
    if (text_out) dprintf(fd, "(0x");

    u64 i = 0;
    if (i < bigint.len && (bigint.ptr[i] & 0xF0) == 0) {
        if (text_out) {
            dprintf(fd, "%x", bigint.ptr[i]);
        } else {
            dprintf(fd, "%X", bigint.ptr[i]);
        }
        i++;
    }

    for (; i < bigint.len; i++) {
        if (text_out) {
            dprintf(fd, "%02x", bigint.ptr[i]);
        } else {
            dprintf(fd, "%02X", bigint.ptr[i]);
        }
    }
    if (text_out) dprintf(fd, ")");
}

static bool
print_bigint(int fd, const char* name, Buffer bigint, bool text_out) {
    u64 i = 0;
    while (i < bigint.len && bigint.ptr[i] == 0) {
        i++;
    }

    // print at least one 0
    if (i == bigint.len && i > 0) {
        i--;
    }

    bigint = buf(bigint.ptr + i, bigint.len - i);
    if (number_too_big(bigint)) return false;

    if (text_out) {
        dprintf(fd, "%s: ", name);
    } else {
        dprintf(fd, "%s=", name);
    }

    if (text_out) {
        print_bigint_dec(fd, bigint);
        dprintf(fd, " ");
    }
    print_bigint_hex(fd, bigint, text_out);
    dprintf(fd, "\n");

    return true;
}

typedef struct {
    Buffer input;
    const char* input_file;
    const char* passphrase;
    int in_fd;
    bool public_key_in;
    bool can_use_stdin;
} RsaParseInput;

static void
print_rsa_error(RsaParseInput* input) {
    dprintf(
        STDERR_FILENO,
        "%s: could not read %s key from %s\n",
        progname,
        input->public_key_in ? "public" : "private",
        input->in_fd == STDIN_FILENO ? "<stdin>" : input->input_file
    );
}

static bool
parse_rsa(RsaParseInput* input, Rsa* rsa, PemKeyType* key_type) {
    *key_type = PemNone;
    Buffer base64_key = { 0 };
    if (input->public_key_in) {
        base64_key = read_public_key(input->input, key_type);
    } else {
        base64_key = read_private_key(input->input, key_type);
    }

    if (!base64_key.ptr) {
        print_rsa_error(input);
        return false;
    }

    Buffer decoded = base64_decode(base64_key);
    if (!decoded.ptr) {
        dprintf(STDERR_FILENO, "%s: invalid base64 input\n", progname);
        return false;
    }

    *rsa = (Rsa){ 0 };
    switch (*key_type) {
        case PemPublic:
        case PemRsaPublic: {
            if (!decode_public_key(decoded, rsa)) {
                print_rsa_error(input);
                return false;
            }
        } break;
        case PemPrivate: {
            if (!decode_private_key(decoded, rsa)) {
                print_rsa_error(input);
                return false;
            }
        } break;
        case PemRsaPrivate: {
            if (!decode_private_rsa_key(decoded, rsa)) {
                print_rsa_error(input);
                return false;
            }
        } break;
        case PemEncPrivate: {
            EncryptedKey enc_key = { 0 };
            if (!decode_encrypted_private_key(decoded, &enc_key)) {
                print_rsa_error(input);
                return false;
            }

            char password[MAX_PASSWORD_SIZE];
            if (!input->passphrase) {
                if (!read_password(buf((u8*)password, MAX_PASSWORD_SIZE), false)) {
                    return false;
                }

                input->passphrase = password;
            }

            u8 key[DES_KEY_SIZE * 3] = { 0 };
            u64 keylen = DES_KEY_SIZE;
            switch (enc_key.algo) {
                case EncryptionDes: {
                    keylen = DES_KEY_SIZE;
                } break;
                case EncryptionDesEde3: {
                    keylen = DES_KEY_SIZE * 3;
                } break;
            }

            pbkdf2_generate(str(input->passphrase), enc_key.pbkdf2_salt, enc_key.pbkdf2_iterations, buf(key, keylen));

            Des64 iv;
            assert(enc_key.iv.len == DES_BLOCK_SIZE);
            ft_memcpy(buf(iv.block, DES_BLOCK_SIZE), enc_key.iv);

            Buffer decrypted = { 0 };
            switch (enc_key.algo) {
                case EncryptionDes: {
                    decrypted = des_cbc_decrypt(enc_key.encrypted_data, buf(key, keylen), iv);
                } break;
                case EncryptionDesEde3: {
                    decrypted = des3_cbc_decrypt(enc_key.encrypted_data, buf(key, keylen), iv);
                } break;
            }

            if (!decrypted.ptr) {
                return false;
            }

            if (!decode_private_key(decrypted, rsa)) {
                print_rsa_error(input);
                return false;
            }
        } break;
        case PemNone: {
            print_rsa_error(input);
        } break;
    }

    return true;
}

static Rsa64
parse_rsa64(Rsa* rsa) {
    Rsa64 rsa64 = (Rsa64){ 0 };
    if (rsa->modulus.len) rsa64.modulus = buffer_to_u64(rsa->modulus);
    if (rsa->pub_exponent.len) rsa64.pub_exponent = buffer_to_u64(rsa->pub_exponent);
    if (rsa->priv_exponent.len) rsa64.priv_exponent = buffer_to_u64(rsa->priv_exponent);
    if (rsa->prime1.len) rsa64.prime1 = buffer_to_u64(rsa->prime1);
    if (rsa->prime2.len) rsa64.prime2 = buffer_to_u64(rsa->prime2);
    if (rsa->exp1.len) rsa64.exp1 = buffer_to_u64(rsa->exp1);
    if (rsa->exp2.len) rsa64.exp2 = buffer_to_u64(rsa->exp2);
    if (rsa->coefficient.len) rsa64.coefficient = buffer_to_u64(rsa->coefficient);
    return rsa64;
}

bool
rsa(RsaOptions* options) {
    bool result = false;

    if (options->use_des && options->use_des3) {
        dprintf(STDERR_FILENO, "%s: -des and -des3 flags set, using -des3\n", progname);
        options->use_des = false;
    }

    int in_fd = get_infile_fd(options->input_file);
    if (in_fd < 0) {
        print_error();
        goto rsa_err;
    }

    int out_fd = get_outfile_fd(options->output_file);
    if (out_fd < 0) {
        print_error();
        goto rsa_err;
    }

    Buffer input = read_all_fd(in_fd, get_filesize(in_fd));

    if (!options->input_format) options->input_format = "PEM";
    if (ft_strcmp(options->input_format, "PEM") != 0) {
        dprintf(STDERR_FILENO, "%s: invalid input format: '%s'\n", progname, options->input_format);
        goto rsa_err;
    }

    if (!options->output_format) options->output_format = "PEM";
    if (ft_strcmp(options->output_format, "PEM") != 0) {
        dprintf(STDERR_FILENO, "%s: invalid output format: '%s'\n", progname, options->output_format);
        goto rsa_err;
    }

    RsaParseInput parse_input = {
        .input = input,
        .in_fd = in_fd,
        .passphrase = options->input_passphrase,
        .input_file = options->input_file,
        .public_key_in = options->public_key_in,
        .can_use_stdin = true,
    };
    Rsa rsa = { 0 };
    PemKeyType key_type = PemNone;

    if (!parse_rsa(&parse_input, &rsa, &key_type)) {
        goto rsa_err;
    }

    if (options->print_key_text) {
        bool success = true;
        if (options->public_key_in) {
            dprintf(STDERR_FILENO, "Public-Key: (64 bit)\n");
            success &= print_bigint(STDERR_FILENO, "Modulus", rsa.modulus, true);
            success &= print_bigint(STDERR_FILENO, "Exponent", rsa.pub_exponent, true);
        } else {
            dprintf(STDERR_FILENO, "Private-Key: (64 bit, 2 primes)\n");
            success &= print_bigint(STDERR_FILENO, "modulus", rsa.modulus, true);
            success &= print_bigint(STDERR_FILENO, "publicExponent", rsa.pub_exponent, true);
            success &= print_bigint(STDERR_FILENO, "privateExponent", rsa.priv_exponent, true);
            success &= print_bigint(STDERR_FILENO, "prime1", rsa.prime1, true);
            success &= print_bigint(STDERR_FILENO, "prime2", rsa.prime2, true);
            success &= print_bigint(STDERR_FILENO, "exponent1", rsa.exp1, true);
            success &= print_bigint(STDERR_FILENO, "exponent2", rsa.exp2, true);
            success &= print_bigint(STDERR_FILENO, "coefficient", rsa.coefficient, true);
        }

        if (!success) {
            dprintf(STDERR_FILENO, "%s: numbers greater than 64bits are not supported\n", progname);
            goto rsa_err;
        }
    }

    if (options->print_modulus) {
        bool success = print_bigint(STDERR_FILENO, "Modulus", rsa.modulus, false);
        if (!success) {
            dprintf(STDERR_FILENO, "%s: numbers greater than 64bits are not supported\n", progname);
            goto rsa_err;
        }
    }

    Rsa64 rsa64 = parse_rsa64(&rsa);

    if (options->verify_key) {
        u64 phi = (rsa64.prime1 - 1) * (rsa64.prime2 - 1);
        bool modulus_ok = rsa64.prime1 * rsa64.prime2 == rsa64.modulus;
        bool priv_exp_ok = inverse_mod(rsa64.pub_exponent, phi) == rsa64.priv_exponent;

        if (modulus_ok && priv_exp_ok) {
            dprintf(STDERR_FILENO, "RSA key ok\n");
        } else {
            dprintf(STDERR_FILENO, "RSA key not ok\n");
        }
    }

    if (!options->no_print_key) {
        dprintf(STDERR_FILENO, "writing RSA key\n");

        if (options->public_key_out || key_type == PemPublic || key_type == PemRsaPublic) {
            output_public_key(rsa64, out_fd);
        } else if (options->use_des || options->use_des3) {
            char password[MAX_PASSWORD_SIZE];
            if (!options->output_passphrase) {
                if (!read_password(buf((u8*)password, MAX_PASSWORD_SIZE), true)) {
                    goto rsa_err;
                }

                options->output_passphrase = password;
            }

            u8 salt[PBKDF2_SALT_SIZE + 1] = { 0 };
            bool success = get_random_bytes(buf(salt, PBKDF2_SALT_SIZE));
            if (!success) {
                dprintf(STDERR_FILENO, "%s: error generating salt\n", progname);
                goto rsa_err;
            }

            output_encoded_private_key(
                rsa64,
                out_fd,
                options->output_passphrase,
                buf(salt, PBKDF2_SALT_SIZE),
                options->use_des ? EncryptionDes : EncryptionDesEde3
            );
        } else {
            output_private_key(rsa64, out_fd);
        }
    }

    result = true;

rsa_err:
    if (options->input_file && in_fd != -1) close(in_fd);
    if (options->output_file && out_fd != -1) close(out_fd);
    return result;
}

static u64
rsa_encrypt(Buffer input, u64 modulus, u64 exponent) {
    u64 data = buffer_to_u64(input);
    u64 result = power_mod(data, exponent, modulus);
    return result;
}

static void
hexdump(Buffer data, int fd, bool decrypt) {
    u32 i = 0;
    if (decrypt) {
        while (data.ptr[i] == 0) {
            i++;
        }
    }

    for (; i < data.len; i += 16) {
        dprintf(fd, "%04x - ", i / 16 * 16);

        u32 j = 0;
        for (; i + j < data.len; j++) {
            dprintf(fd, "%02x ", data.ptr[i + j]);
        }
        for (; j < 16; j++) {
            dprintf(fd, "   ");
        }

        dprintf(fd, "  ");

        j = 0;
        for (; i + j < data.len; j++) {
            char c = '.';
            if (ft_isprint(data.ptr[i + j])) {
                c = data.ptr[i + j];
            }
            dprintf(fd, "%c", c);
        }
        for (; j < 16; j++) {
            dprintf(fd, " ");
        }

        dprintf(fd, "\n");
    }
}

bool
rsautl(RsaUtlOptions* options) {
    bool result = false;

    if (!options->input_key) {
        dprintf(STDERR_FILENO, "%s: input key is required\n", progname);
        goto rsautl_err;
    }

    if (options->encrypt && options->decrypt) {
        dprintf(STDERR_FILENO, "%s: cannot encrypt and decrypt at the same time\n", progname);
        goto rsautl_err;
    }

    if (!options->encrypt && !options->decrypt) options->encrypt = true;

    int in_fd = get_infile_fd(options->input_file);
    if (in_fd < 0) {
        print_error();
        goto rsautl_err;
    }

    int out_fd = get_outfile_fd(options->output_file);
    if (out_fd < 0) {
        print_error();
        goto rsautl_err;
    }

    int key_fd = open(options->input_key, O_RDONLY);
    if (key_fd < 0) {
        print_error();
        goto rsautl_err;
    }

    Buffer key_input = read_all_fd(key_fd, get_filesize(key_fd));

    RsaParseInput parse_input = {
        .input = key_input,
        .in_fd = key_fd,
        .input_file = options->input_key,
        .passphrase = NULL,
        .public_key_in = options->public_key_in,
        .can_use_stdin = false,
    };
    Rsa rsa = { 0 };
    PemKeyType key_type = PemNone;
    if (!parse_rsa(&parse_input, &rsa, &key_type)) {
        goto rsautl_err;
    }

    Rsa64 rsa64 = parse_rsa64(&rsa);

    Buffer input = read_all_fd(in_fd, get_filesize(in_fd));
    if (input.len > sizeof(u64)) {
        dprintf(STDERR_FILENO, "%s: message must be <= 8 bytes\n", progname);
        goto rsautl_err;
    }

    u64 rsa_output = rsa_encrypt(input, rsa64.modulus, options->decrypt ? rsa64.priv_exponent : rsa64.pub_exponent);
    rsa_output = byte_swap64(rsa_output);

    if (options->hexdump) {
        hexdump(buf((u8*)&rsa_output, sizeof(rsa_output)), out_fd, options->decrypt);
    } else {
        (void)write(out_fd, &rsa_output, sizeof(rsa_output));
    }

rsautl_err:
    if (options->input_file && in_fd != -1) close(in_fd);
    if (options->output_file && out_fd != -1) close(out_fd);
    return result;
}
