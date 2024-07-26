#pragma once

#include "ssl.h"
#include "types.h"

bool
is_prime(u64 n);

bool
genrsa(GenRsaOptions* options);
