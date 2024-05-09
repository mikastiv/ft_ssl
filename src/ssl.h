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
    CMD_NONE,
    CMD_MD5,
    CMD_SHA256,
} Command;

