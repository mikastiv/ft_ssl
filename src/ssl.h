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

typedef struct {
    bool quiet;
    bool reverse_fmt;
    bool echo_stdin;
    const char* string_argument;
} DigestOptions;

typedef struct {
    bool encode;
    bool decode;
    const char* input_file;
    const char* output_file;
} Base64Options;

typedef struct {
    bool use_base64;
    bool decrypt;
    bool encrypt;
    const char* input_file;
    const char* output_file;
    const char* hex_key;
    const char* password;
    const char* hex_salt;
    const char* hex_iv;
} DesOptions;

typedef enum {
    Command_None,
    Command_Md5,
    Command_Sha256,
    Command_Sha224,
    Command_Sha512,
    Command_Sha384,
    Command_Whirlpool,
    Command_LastDigest = Command_Whirlpool,
    Command_Base64,
    Command_Des,
    Command_DesEcb,
    Command_DesCbc,
    Command_DesOfb,
    Command_DesCfb,
    Command_Des3,
    Command_Des3Ecb,
    Command_Des3Cbc,
} Command;

bool
digest(u32 first_input, Command cmd, DigestOptions options);
