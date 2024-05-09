#pragma once

#include <stdbool.h>

typedef struct {
    bool print_help;
    bool quiet;
    bool reverse_fmt;
    bool print_sum;
    bool echo_stdin;
} Options;

typedef enum {
    MD5,
    SHA256,
} Command;
