#pragma once

#include "ssl.h"
#include "types.h"

typedef struct {
    u64 prime1;
    u64 prime2;
    u64 modulus;
    u64 phi;
    u64 pub_exponent;
    u64 priv_exponent;
    u64 exp1;
    u64 exp2;
    u64 coefficient;
} Rsa;

bool
genrsa(GenRsaOptions* options);

bool
rsa(RsaOptions* options);
