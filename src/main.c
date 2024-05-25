#include "ssl.h"
#include "types.h"
#include "utils.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char* progname;
Options options;

const char* cmd_names[] = {
    [CMD_NONE] = "none",           [CMD_MD5] = "md5",        [CMD_SHA256] = "sha256",
    [CMD_SHA224] = "sha224",       [CMD_SHA512] = "sha512",  [CMD_SHA384] = "sha384",
    [CMD_WHIRLPOOL] = "whirlpool", [CMD_BASE64] = "base64",  [CMD_DES] = "des",
    [CMD_DES_ECB] = "des-ecb",     [CMD_DES_CBC] = "des-cbc"
};

static void
usage(void) {
    dprintf(STDERR_FILENO, "usage: %s command [flags] [file/string]\n", progname);
}

static void
print_flag(char f, const char* desc) {
    dprintf(STDERR_FILENO, "    -%c: %s\n", f, desc);
}

static void
print_help(void) {
    usage();

    dprintf(STDERR_FILENO, "\nStandard commands:\n");

    dprintf(STDERR_FILENO, "\nMessage Digest commands:\n");
    for (u64 i = CMD_NONE + 1; i <= CMD_LAST_DIGEST; i++) {
        dprintf(STDERR_FILENO, "    %s\n", cmd_names[i]);
    }

    dprintf(STDERR_FILENO, "\nCipher commands:\n");
    for (u64 i = CMD_LAST_DIGEST + 1; i < array_len(cmd_names); i++) {
        dprintf(STDERR_FILENO, "    %s\n", cmd_names[i]);
    }

    dprintf(STDERR_FILENO, "\nFlags:\n");
    print_flag('h', "print help");
    print_flag('p', "echo STDIN to STDOUT and append the checksum to STDOUT");
    print_flag('q', "quiet mode");
    print_flag('r', "reverse the format of the output");
    print_flag('s', "print the sum of the given string");
}

static void
unknown_flag(const char* flag) {
    dprintf(STDERR_FILENO, "%s: unknown flag: '%s'\n", progname, flag);
    print_help();
    exit(EXIT_FAILURE);
}

static u32
parse_flags(int argc, char** argv) {
    for (int i = 2; i < argc; i++) {
        if (argv[i][0] != '-') return i;
        if (ft_strlen(&argv[i][1]) != 1) unknown_flag(argv[i]);

        switch (argv[i][1]) {
            case 'h': {
                options.print_help = true;
            } break;
            case 'p': {
                options.echo_stdin = true;
            } break;
            case 'r': {
                options.reverse_fmt = true;
            } break;
            case 's': {
                options.first_is_string = true;
            } break;
            case 'q': {
                options.quiet = true;
            } break;
            case 'd':
            case 'e': {
                if (argv[i][1] == 'e') options.encode = true;
                if (argv[i][1] == 'd') options.decode = true;

                if (options.encode && options.decode) {
                    dprintf(STDERR_FILENO, "%s: cannot use encode and decode together\n", progname);
                    exit(EXIT_FAILURE);
                }
            } break;
            case 'i': {
                i++;
                if (i >= argc) {
                    dprintf(STDERR_FILENO, "%s: '-i': missing input file\n", progname);
                    exit(EXIT_FAILURE);
                }
                if (options.input_file) {
                    dprintf(STDERR_FILENO, "%s: cannot use multiple input files\n", progname);
                    exit(EXIT_FAILURE);
                }

                options.input_file = argv[i];
            } break;
            case 'o': {
                i++;
                if (i >= argc) {
                    dprintf(STDERR_FILENO, "%s: '-o': missing output file\n", progname);
                    exit(EXIT_FAILURE);
                }
                if (options.output_file) {
                    dprintf(STDERR_FILENO, "%s: cannot use multiple output files\n", progname);
                    exit(EXIT_FAILURE);
                }

                options.output_file = argv[i];
            } break;
            default: {
                unknown_flag(argv[i]);
            } break;
        }
    }
    return argc;
}

static Command
parse_command(const char* str) {
    for (u64 i = 0; i < array_len(cmd_names); i++) {
        if (ft_strcmp(cmd_names[i], str) == 0) return (Command)i;
    }

    return CMD_NONE;
}

static void
unsupported_flag(char flag, Command cmd) {
    dprintf(STDERR_FILENO, "%s: %s: unsupported flag '-%c'\n", progname, cmd_names[cmd], flag);
    exit(EXIT_FAILURE);
}

int
main(int argc, char** argv) {
    if (argc > 0) progname = argv[0];
    if (argc < 2) {
        usage();
        return EXIT_FAILURE;
    }

    Command cmd = parse_command(argv[1]);
    if (cmd == CMD_NONE) {
        dprintf(STDERR_FILENO, "%s: unknown command: '%s'\n", progname, argv[1]);
        print_help();
        return EXIT_FAILURE;
    }

    u32 first_input = 2;
    if (argc > 2) {
        first_input = parse_flags(argc, argv);
    }

    if (options.print_help) {
        print_help();
        return EXIT_FAILURE;
    }

    switch (cmd) {
        case CMD_MD5:
        case CMD_SHA256:
        case CMD_SHA224:
        case CMD_SHA512:
        case CMD_SHA384:
        case CMD_WHIRLPOOL: {
            if (options.decode) unsupported_flag('d', cmd);
            if (options.encode) unsupported_flag('e', cmd);
            if (options.input_file) unsupported_flag('i', cmd);
            if (options.output_file) unsupported_flag('o', cmd);

            bool success = digest(argc, argv, first_input, cmd);
            if (!success) return EXIT_FAILURE;
        } break;
        case CMD_BASE64:
        case CMD_DES:
        case CMD_DES_ECB:
        case CMD_DES_CBC: {
            if (options.quiet) unsupported_flag('q', cmd);
            if (options.echo_stdin) unsupported_flag('p', cmd);
            if (options.reverse_fmt) unsupported_flag('r', cmd);
            if (options.first_is_string) unsupported_flag('s', cmd);
        } break;
        case CMD_NONE: {
            dprintf(STDERR_FILENO, "Unreachable\n");
            return EXIT_FAILURE;
        } break;
    }
}
