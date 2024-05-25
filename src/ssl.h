#pragma once

#include "types.h"

#include <stdbool.h>

typedef struct {
    bool print_help;
    bool quiet;
    bool reverse_fmt;
    bool first_is_string;
    bool echo_stdin;
    bool encode;
    bool decode;
    const char* input_file;
    const char* output_file;
} Options;

typedef enum {
    CMD_NONE,
    CMD_MD5,
    CMD_SHA256,
    CMD_SHA224,
    CMD_SHA512,
    CMD_SHA384,
    CMD_WHIRLPOOL,
    CMD_LAST_DIGEST = CMD_WHIRLPOOL,
    CMD_BASE64,
    CMD_DES,
    CMD_DES_ECB,
    CMD_DES_CBC,
} Command;

bool
digest(int argc, char** argv, u32 first_input, Command cmd);
