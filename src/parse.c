#include "ssl.h"

#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "globals.h"

static const char* cmd_names[] = {
    [Command_None] = "none",
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
    char flag;
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

void
usage(const char* command) {
    dprintf(STDERR_FILENO, "usage: %s %s [flags] [file/string]\n", progname, command ? command : "command");
}

static void
print_flag(char f, const char* desc) {
    dprintf(STDERR_FILENO, "    -%c: %s\n", f, desc);
}

void
print_help(Command cmd) {

    switch (cmd) {
        case Command_None:
            usage(0);
            dprintf(STDERR_FILENO, "\nGeneral flags:\n");
            print_flag('h', "print help");

            dprintf(STDERR_FILENO, "\nStandard commands:\n");

            dprintf(STDERR_FILENO, "\nMessage Digest commands:\n");
            for (u64 i = Command_None + 1; i <= Command_LastDigest; i++) {
                dprintf(STDERR_FILENO, "    %s\n", cmd_names[i]);
            }
            dprintf(STDERR_FILENO, "\nCipher commands:\n");
            for (u64 i = Command_LastDigest + 1; i < array_len(cmd_names); i++) {
                dprintf(STDERR_FILENO, "    %s\n", cmd_names[i]);
            }
            break;
        case Command_Md5:
        case Command_Sha256:
        case Command_Sha224:
        case Command_Sha512:
        case Command_Sha384:
        case Command_Whirlpool:
            usage(cmd_names[cmd]);

            dprintf(STDERR_FILENO, "\nFlags:\n");
            print_flag('h', "print help");
            print_flag('p', "echo STDIN to STDOUT and append the checksum to STDOUT");
            print_flag('q', "quiet mode");
            print_flag('r', "reverse the format of the output");
            print_flag('s', "print the sum of the given string");
            break;
        case Command_Base64:
            usage(cmd_names[cmd]);

            dprintf(STDERR_FILENO, "\nFlags:\n");
            print_flag('d', "decode mode");
            print_flag('e', "encode mode (default)");
            print_flag('i', "input file for message");
            print_flag('o', "output file for message");
            break;
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
        case Command_Des3Pcbc:
            usage(cmd_names[cmd]);

            dprintf(STDERR_FILENO, "\nFlags:\n");
            print_flag('d', "decrypt mode");
            print_flag('e', "encrypt mode (default)");
            print_flag('i', "input file for message");
            print_flag('o', "output file for message");
            print_flag('a', "decode/encode the input/output in base64");
            print_flag('k', "key in hex");
            print_flag('s', "salt in hex");
            print_flag('v', "initialization vector in hex");
            print_flag('p', "password");
            break;
    }
}

static void
unknown_flag(const char* flag) {
    dprintf(STDERR_FILENO, "%s: unknown flag: '%s'\n", progname, flag);
    exit(EXIT_FAILURE);
}

static void
check_next_argument(u32 index, char flag) {
    if (index + 1 >= argc) {
        dprintf(STDERR_FILENO, "%s: '-%c': missing value\n", progname, flag);
        exit(EXIT_FAILURE);
    }
}

static void
duplicate_flag(char flag) {
    dprintf(STDERR_FILENO, "%s: duplicate flag: '-%c'\n", progname, flag);
    exit(EXIT_FAILURE);
}

static bool
parse_flag(const char flag, const Option* options, u64 size, u32* index) {
    for (u32 j = 0; j < size; j++) {
        Option op = options[j];
        if (flag == op.flag) {
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
        if (ft_strlen(&argv[i][1]) != 1) unknown_flag(argv[i]);

        const char flag = argv[i][1];
        if (flag == 'h') {
            print_help(cmd);
            exit(EXIT_FAILURE);
        }

        switch (cmd) {
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
                     .flag = 'p',
                     .type = OptionType_Bool,
                     .value = &options->echo_stdin,
                     },
                    {
                     .name = "reverse format",
                     .flag = 'r',
                     .type = OptionType_Bool,
                     .value = &options->reverse_fmt,
                     },
                    {
                     .name = "string argument",
                     .flag = 's',
                     .type = OptionType_String,
                     .value = &options->string_argument,
                     },
                    {
                     .name = "quiet",
                     .flag = 'q',
                     .type = OptionType_Bool,
                     .value = &options->quiet,
                     },
                };

                bool found = parse_flag(flag, digest_options, array_len(digest_options), &i);
                if (!found) {
                    unknown_flag(argv[i]);
                }
            } break;
            case Command_Base64: {
                Base64Options* options = out_options;
                const Option base64_options[] = {
                    {
                     .name = "encode",
                     .flag = 'e',
                     .type = OptionType_Bool,
                     .value = &options->encode,
                     },
                    {
                     .name = "decode",
                     .flag = 'd',
                     .type = OptionType_Bool,
                     .value = &options->decode,
                     },
                    {
                     .name = "input file",
                     .flag = 'i',
                     .type = OptionType_String,
                     .value = &options->input_file,
                     },
                    {
                     .name = "output file",
                     .flag = 'o',
                     .type = OptionType_String,
                     .value = &options->output_file,
                     },
                };

                bool found = parse_flag(flag, base64_options, array_len(base64_options), &i);
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
                     .flag = 'a',
                     .type = OptionType_Bool,
                     .value = &options->use_base64,
                     },
                    {
                     .name = "decrypt",
                     .flag = 'd',
                     .type = OptionType_Bool,
                     .value = &options->decrypt,
                     },
                    {
                     .name = "encrypt",
                     .flag = 'e',
                     .type = OptionType_Bool,
                     .value = &options->encrypt,
                     },
                    {
                     .name = "input file",
                     .flag = 'i',
                     .type = OptionType_String,
                     .value = &options->input_file,
                     },
                    {
                     .name = "output file",
                     .flag = 'o',
                     .type = OptionType_String,
                     .value = &options->output_file,
                     },
                    {
                     .name = "hex key",
                     .flag = 'k',
                     .type = OptionType_String,
                     .value = &options->hex_key,
                     },
                    {
                     .name = "hex salt",
                     .flag = 's',
                     .type = OptionType_String,
                     .value = &options->hex_salt,
                     },
                    {
                     .name = "hex iv",
                     .flag = 'v',
                     .type = OptionType_String,
                     .value = &options->hex_iv,
                     },
                    {
                     .name = "password",
                     .flag = 'p',
                     .type = OptionType_String,
                     .value = &options->password,
                     },
                };

                bool found = parse_flag(flag, des_options, array_len(des_options), &i);
                if (!found) {
                    unknown_flag(argv[i]);
                }
            } break;
            default: {
            } break;
        }
    }

    return argc;
}
