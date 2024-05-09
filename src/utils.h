#pragma once

#include "types.h"

#define array_len(array) (sizeof(array) / sizeof(array[0]))

u64
ft_strlen(const char* str);

i64
ft_strcmp(const char* s1, const char* s2);
