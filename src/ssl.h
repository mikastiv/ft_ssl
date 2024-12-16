#pragma once

#define MAX_MEMORY (1024 * 1024 * 64)

#include "types.h"

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

typedef struct {
    const char* input_file;
    const char* output_file;
} GenRsaOptions;

typedef struct {
    const char* input_format;
    const char* output_format;
    const char* input_file;
    const char* output_file;
    const char* input_passphrase;
    const char* output_passphrase;
    bool public_key_in;
    bool public_key_out;
    bool use_des;
    bool use_des3;
    bool print_key_text;
    bool no_print_key;
    bool print_modulus;
    bool verify_key;
} RsaOptions;

typedef struct {
    const char* input_file;
    const char* output_file;
    const char* input_key;
    bool public_key_in;
    bool encrypt;
    bool decrypt;
    bool hexdump;
} RsaUtlOptions;

typedef enum {
    Command_None,
    Command_GenRsa,
    Command_Rsa,
    Command_RsaUtl,
    Command_LastStandard = Command_RsaUtl,
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
    Command_DesPcbc,
    Command_Des3,
    Command_Des3Ecb,
    Command_Des3Cbc,
    Command_Des3Ofb,
    Command_Des3Cfb,
    Command_Des3Pcbc,
    Command_LastCipher = Command_Des3Pcbc,
} Command;

bool
digest(u32 first_input, Command cmd, DigestOptions options);

bool
base64(Base64Options* options);

bool
cipher(Command cmd, DesOptions* options);
