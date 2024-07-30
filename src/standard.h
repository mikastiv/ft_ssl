#pragma once

#include "ssl.h"
#include "types.h"

typedef struct {
    u64 prime1;
    u64 prime2;
    u64 modulus;
    u64 pub_exponent;
    u64 priv_exponent;
    u64 exp1;
    u64 exp2;
    u64 coefficient;
} Rsa64;

typedef struct {
    Buffer prime1;
    Buffer prime2;
    Buffer modulus;
    Buffer pub_exponent;
    Buffer priv_exponent;
    Buffer exp1;
    Buffer exp2;
    Buffer coefficient;
} Rsa;

bool
genrsa(GenRsaOptions* options);

bool
rsa(RsaOptions* options);
