#include "ssl.h"

#include "arena.h"
#include "globals.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const char* cmd_names[] = {
    [Command_None] = "none",
    [Command_GenRsa] = "genrsa",
    [Command_Rsa] = "rsa",
    [Command_RsaUtl] = "rsautl",
    [Command_Md5] = "md5",
    [Command_Sha256] = "sha256",
    [Command_Sha224] = "sha224",
    [Command_Sha512] = "sha512",
    [Command_Sha384] = "sha384",
    [Command_Whirlpool] = "whirlpool",
    [Command_Base64] = "base64",
    [Command_Des] = "des",
    [Command_DesEcb] = "des-ecb",
    [Command_DesCbc] = "des-cbc",
    [Command_DesOfb] = "des-ofb",
    [Command_DesCfb] = "des-cfb",
    [Command_DesPcbc] = "des-pcbc",
    [Command_Des3] = "des3",
    [Command_Des3Ecb] = "des3-ecb",
    [Command_Des3Cbc] = "des3-cbc",
    [Command_Des3Ofb] = "des3-ofb",
    [Command_Des3Cfb] = "des3-cfb",
    [Command_Des3Pcbc] = "des3-pcbc",
};

typedef enum {
    OptionType_Bool,
    OptionType_String,
} OptionType;

typedef struct {
    const char* name;
    const char* flag;
    OptionType type;
    void* value;
} Option;

Command
parse_command(const char* str) {
    for (u64 i = 0; i < array_len(cmd_names); i++) {
        if (ft_strcmp(cmd_names[i], str) == 0) return (Command)i;
    }

    return Command_None;
}

static void
print_flag(const char* flag, const char* desc) {
    dprintf(STDERR_FILENO, "    -%-20s %s\n", flag, desc);
}

void
print_help(Command cmd) {

    switch (cmd) {
        case Command_None: {
            dprintf(STDERR_FILENO, "usage: %s [command]\n", progname);
            dprintf(STDERR_FILENO, "\nGeneral flags:\n");
            print_flag("h", "print help");

            dprintf(STDERR_FILENO, "\nStandard commands:\n");
            for (u64 i = Command_None + 1; i <= Command_LastStandard; i++) {
                dprintf(STDERR_FILENO, "    %s\n", cmd_names[i]);
            }
            dprintf(STDERR_FILENO, "\nMessage Digest commands:\n");
            for (u64 i = Command_LastStandard + 1; i <= Command_LastDigest; i++) {
                dprintf(STDERR_FILENO, "    %s\n", cmd_names[i]);
            }
            dprintf(STDERR_FILENO, "\nCipher commands:\n");
            for (u64 i = Command_LastDigest + 1; i < array_len(cmd_names); i++) {
                dprintf(STDERR_FILENO, "    %s\n", cmd_names[i]);
            }
        } break;
        case Command_GenRsa: {
            dprintf(STDERR_FILENO, "usage: %s %s [flags]\n", progname, cmd_names[cmd]);

            dprintf(STDERR_FILENO, "\nFlags:\n");
            print_flag("h", "print help");
            print_flag("i <filename>", "input file");
            print_flag("o <filename>", "output file");
        } break;
        case Command_Rsa: {
            dprintf(STDERR_FILENO, "usage: %s %s [flags]\n", progname, cmd_names[cmd]);

            dprintf(STDERR_FILENO, "\nFlags:\n");
            print_flag("h", "print help");
            print_flag("inform <format>", "input format; available: PEM");
            print_flag("outform <format>", "output format; available: PEM");
            print_flag("in <filename>", "input file");
            print_flag("out <filename>", "output file");
            print_flag("passin <filename>", "input file pass phrase source");
            print_flag("passout <filename>", "output file pass phrase source");
            print_flag("des", "use DES cipher");
            print_flag("text", "print the key in text");
            print_flag("noout", "don't print key out");
            print_flag("modulus", "print the RSA key modulus");
            print_flag("check", "verify key consistency");
            print_flag("pubin", "expect a public key in input file");
            print_flag("pubout", "output a public key");
        } break;
        case Command_RsaUtl: {
            dprintf(STDERR_FILENO, "usage: %s %s [flags]\n", progname, cmd_names[cmd]);

            dprintf(STDERR_FILENO, "\nFlags:\n");
            print_flag("h", "print help");
            print_flag("in <filename>", "input file");
            print_flag("out <filename>", "output file");
            print_flag("inkey <filename>", "input key");
            print_flag("pubin", "expect a public key in input file");
            print_flag("encrypt", "encrypt with public key");
            print_flag("decrypt", "decrypt with private key");
            print_flag("hexdump", "hex dump output");
        } break;
        case Command_Md5:
        case Command_Sha256:
        case Command_Sha224:
        case Command_Sha512:
        case Command_Sha384:
        case Command_Whirlpool: {
            dprintf(STDERR_FILENO, "usage: %s %s [flags] [files]\n", progname, cmd_names[cmd]);

            dprintf(STDERR_FILENO, "\nFlags:\n");
            print_flag("h", "print help");
            print_flag("p", "echo STDIN to STDOUT and append the checksum to STDOUT");
            print_flag("q", "quiet mode");
            print_flag("r", "reverse the format of the output");
            print_flag("s <string>", "print the sum of the given string");
        } break;
        case Command_Base64: {
            dprintf(STDERR_FILENO, "usage: %s %s [flags]\n", progname, cmd_names[cmd]);

            dprintf(STDERR_FILENO, "\nFlags:\n");
            print_flag("h", "print help");
            print_flag("d", "decode mode");
            print_flag("e", "encode mode (default)");
            print_flag("i <filename>", "input file for message");
            print_flag("o <filename>", "output file for message");
        } break;
        case Command_Des:
        case Command_DesEcb:
        case Command_DesCbc:
        case Command_DesOfb:
        case Command_DesCfb:
        case Command_DesPcbc:
        case Command_Des3:
        case Command_Des3Ecb:
        case Command_Des3Cbc:
        case Command_Des3Ofb:
        case Command_Des3Cfb:
        case Command_Des3Pcbc: {
            dprintf(STDERR_FILENO, "usage: %s %s [flags]\n", progname, cmd_names[cmd]);

            dprintf(STDERR_FILENO, "\nFlags:\n");
            print_flag("h", "print help");
            print_flag("d", "decrypt mode");
            print_flag("e", "encrypt mode (default)");
            print_flag("i <filename>", "input file for message");
            print_flag("o <filename>", "output file for message");
            print_flag("a", "decode/encode the input/output in base64");
            print_flag("k <hex key>", "key in hex");
            print_flag("s <hex salt>", "salt in hex");
            print_flag("v <hex iv>", "initialization vector in hex");
            print_flag("p <password>", "password");
        } break;
    }
}

static void
unknown_flag(const char* flag) {
    dprintf(STDERR_FILENO, "%s: unknown flag: '%s'\n", progname, flag);
    arena_free(&arena);
    exit(EXIT_FAILURE);
}

static void
check_next_argument(u32 index, const char* flag) {
    if (index + 1 >= argc) {
        dprintf(STDERR_FILENO, "%s: '-%s': missing value\n", progname, flag);
        arena_free(&arena);
        exit(EXIT_FAILURE);
    }
}

static void
duplicate_flag(const char* flag) {
    dprintf(STDERR_FILENO, "%s: duplicate flag: '-%s'\n", progname, flag);
    arena_free(&arena);
    exit(EXIT_FAILURE);
}

static bool
parse_flags(const char* flag, const Option* options, u64 size, u32* index) {
    for (u32 j = 0; j < size; j++) {
        Option op = options[j];
        if (ft_strcmp(flag, op.flag) == 0) {
            switch (op.type) {
                case OptionType_String: {
                    const char** value = options[j].value;
                    if (*value) duplicate_flag(flag);
                    check_next_argument(*index, flag);
                    *index += 1;
                    *value = argv[*index];
                } break;
                case OptionType_Bool: {
                    bool* value = options[j].value;
                    *value = true;
                } break;
            }

            return true;
        }
    }

    return false;
}

u32
parse_options(Command cmd, void* out_options) {
    for (u32 i = 2; i < argc; i++) {
        if (argv[i][0] != '-') return i;

        const char* flag = &argv[i][1];
        if (ft_strcmp(flag, "h") == 0) {
            print_help(cmd);
            arena_free(&arena);
            exit(EXIT_FAILURE);
        }

        switch (cmd) {
            case Command_GenRsa: {
                GenRsaOptions* options = out_options;
                const Option genrsa_options[] = {
                    {
                     .name = "input file",
                     .flag = "i",
                     .type = OptionType_String,
                     .value = &options->input_file,
                     },
                    {
                     .name = "output file",
                     .flag = "o",
                     .type = OptionType_String,
                     .value = &options->output_file,
                     },
                };

                bool found = parse_flags(flag, genrsa_options, array_len(genrsa_options), &i);
                if (!found) {
                    unknown_flag(argv[i]);
                }
            } break;
            case Command_Rsa: {
                RsaOptions* options = out_options;
                const Option rsa_options[] = {
                    {
                     .name = "input format",
                     .flag = "inform",
                     .type = OptionType_String,
                     .value = &options->input_format,
                     },
                    {
                     .name = "output format",
                     .flag = "outform",
                     .type = OptionType_String,
                     .value = &options->output_format,
                     },
                    {
                     .name = "input file",
                     .flag = "in",
                     .type = OptionType_String,
                     .value = &options->input_file,
                     },
                    {
                     .name = "output file",
                     .flag = "out",
                     .type = OptionType_String,
                     .value = &options->output_file,
                     },
                    {
                     .name = "input file pass phrase source",
                     .flag = "passin",
                     .type = OptionType_String,
                     .value = &options->input_passphrase_file,
                     },
                    {
                     .name = "output file pass phrase source",
                     .flag = "passout",
                     .type = OptionType_String,
                     .value = &options->output_passphrase_file,
                     },
                    {
                     .name = "use DES",
                     .flag = "des",
                     .type = OptionType_Bool,
                     .value = &options->use_des,
                     },
                    {
                     .name = "print key text",
                     .flag = "text",
                     .type = OptionType_Bool,
                     .value = &options->print_key_text,
                     },
                    {
                     .name = "no print key",
                     .flag = "noout",
                     .type = OptionType_Bool,
                     .value = &options->no_print_key,
                     },
                    {
                     .name = "print modulus",
                     .flag = "modulus",
                     .type = OptionType_Bool,
                     .value = &options->print_modulus,
                     },
                    {
                     .name = "verify key",
                     .flag = "check",
                     .type = OptionType_Bool,
                     .value = &options->verify_key,
                     },
                    {
                     .name = "input file is pubkey",
                     .flag = "pubin",
                     .type = OptionType_Bool,
                     .value = &options->is_public_key_input_file,
                     },
                    {
                     .name = "output file is pubkey",
                     .flag = "pubout",
                     .type = OptionType_Bool,
                     .value = &options->is_public_key_output_file,
                     }
                };

                bool found = parse_flags(flag, rsa_options, array_len(rsa_options), &i);
                if (!found) {
                    unknown_flag(argv[i]);
                }
            } break;
            case Command_RsaUtl: {
                RsaUtlOptions* options = out_options;
                const Option rsautl_options[] = {
                    {
                     .name = "input file",
                     .flag = "in",
                     .type = OptionType_String,
                     .value = &options->input_file,
                     },
                    {
                     .name = "output file",
                     .flag = "out",
                     .type = OptionType_String,
                     .value = &options->output_file,
                     },
                    {
                     .name = "input key",
                     .flag = "inkey",
                     .type = OptionType_String,
                     .value = &options->input_key,
                     },
                    {
                     .name = "input file is pubkey",
                     .flag = "pubin",
                     .type = OptionType_Bool,
                     .value = &options->is_public_key_input_file,
                     },
                    {
                     .name = "encrypt",
                     .flag = "encrypt",
                     .type = OptionType_Bool,
                     .value = &options->encrypt,
                     },
                    {
                     .name = "decrypt",
                     .flag = "decrypt",
                     .type = OptionType_Bool,
                     .value = &options->decrypt,
                     },
                    {
                     .name = "hexdump",
                     .flag = "hexdump",
                     .type = OptionType_Bool,
                     .value = &options->hexdump,
                     }
                };

                bool found = parse_flags(flag, rsautl_options, array_len(rsautl_options), &i);
                if (!found) {
                    unknown_flag(argv[i]);
                }
            } break;
            case Command_Md5:
            case Command_Sha256:
            case Command_Sha224:
            case Command_Sha512:
            case Command_Sha384:
            case Command_Whirlpool: {
                DigestOptions* options = out_options;
                const Option digest_options[] = {
                    {
                     .name = "echo stdin",
                     .flag = "p",
                     .type = OptionType_Bool,
                     .value = &options->echo_stdin,
                     },
                    {
                     .name = "reverse format",
                     .flag = "r",
                     .type = OptionType_Bool,
                     .value = &options->reverse_fmt,
                     },
                    {
                     .name = "string argument",
                     .flag = "s",
                     .type = OptionType_String,
                     .value = &options->string_argument,
                     },
                    {
                     .name = "quiet",
                     .flag = "q",
                     .type = OptionType_Bool,
                     .value = &options->quiet,
                     },
                };

                bool found = parse_flags(flag, digest_options, array_len(digest_options), &i);
                if (!found) {
                    unknown_flag(argv[i]);
                }
            } break;
            case Command_Base64: {
                Base64Options* options = out_options;
                const Option base64_options[] = {
                    {
                     .name = "encode",
                     .flag = "e",
                     .type = OptionType_Bool,
                     .value = &options->encode,
                     },
                    {
                     .name = "decode",
                     .flag = "d",
                     .type = OptionType_Bool,
                     .value = &options->decode,
                     },
                    {
                     .name = "input file",
                     .flag = "i",
                     .type = OptionType_String,
                     .value = &options->input_file,
                     },
                    {
                     .name = "output file",
                     .flag = "o",
                     .type = OptionType_String,
                     .value = &options->output_file,
                     },
                };

                bool found = parse_flags(flag, base64_options, array_len(base64_options), &i);
                if (!found) {
                    unknown_flag(argv[i]);
                }
            } break;
            case Command_Des:
            case Command_DesEcb:
            case Command_DesCbc:
            case Command_DesOfb:
            case Command_DesCfb:
            case Command_DesPcbc:
            case Command_Des3:
            case Command_Des3Ecb:
            case Command_Des3Cbc:
            case Command_Des3Ofb:
            case Command_Des3Cfb:
            case Command_Des3Pcbc: {
                DesOptions* options = out_options;
                const Option des_options[] = {
                    {
                     .name = "use base64",
                     .flag = "a",
                     .type = OptionType_Bool,
                     .value = &options->use_base64,
                     },
                    {
                     .name = "decrypt",
                     .flag = "d",
                     .type = OptionType_Bool,
                     .value = &options->decrypt,
                     },
                    {
                     .name = "encrypt",
                     .flag = "e",
                     .type = OptionType_Bool,
                     .value = &options->encrypt,
                     },
                    {
                     .name = "input file",
                     .flag = "i",
                     .type = OptionType_String,
                     .value = &options->input_file,
                     },
                    {
                     .name = "output file",
                     .flag = "o",
                     .type = OptionType_String,
                     .value = &options->output_file,
                     },
                    {
                     .name = "hex key",
                     .flag = "k",
                     .type = OptionType_String,
                     .value = &options->hex_key,
                     },
                    {
                     .name = "hex salt",
                     .flag = "s",
                     .type = OptionType_String,
                     .value = &options->hex_salt,
                     },
                    {
                     .name = "hex iv",
                     .flag = "v",
                     .type = OptionType_String,
                     .value = &options->hex_iv,
                     },
                    {
                     .name = "password",
                     .flag = "p",
                     .type = OptionType_String,
                     .value = &options->password,
                     },
                };

                bool found = parse_flags(flag, des_options, array_len(des_options), &i);
                if (!found) {
                    unknown_flag(argv[i]);
                }
            } break;
            case Command_None: {
                dprintf(STDERR_FILENO, "unreachable code\n");
                arena_free(&arena);
                exit(EXIT_FAILURE);
            } break;
        }
    }

    return argc;
}
