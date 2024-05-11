#pragma once

#include <stdbool.h>

typedef struct {
    bool print_help;
    bool quiet;
    bool reverse_fmt;
    bool first_is_string;
    bool echo_stdin;
} Options;

typedef enum {
    CMD_NONE,
    CMD_MD5,
    CMD_SHA256,
    CMD_SHA224,
    CMD_SHA512,
    CMD_SHA384,
} Command;
