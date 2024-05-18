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
    [CMD_NONE] = "none",           [CMD_MD5] = "md5",       [CMD_SHA256] = "sha256",
    [CMD_SHA224] = "sha224",       [CMD_SHA512] = "sha512", [CMD_SHA384] = "sha384",
    [CMD_WHIRLPOOL] = "whirlpool",
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
    dprintf(STDERR_FILENO, "\nCommands:\n");
    for (u64 i = CMD_NONE + 1; i < array_len(cmd_names); i++) {
        dprintf(STDERR_FILENO, "    %s\n", cmd_names[i]);
    }

    dprintf(STDERR_FILENO, "\nFlags:\n");
    print_flag('h', "print help");
    print_flag('p', "echo STDIN to STDOUT and append the checksum to STDOUT");
    print_flag('q', "quiet mode");
    print_flag('r', "reverse the format of the output");
    print_flag('s', "print the sum of the given string");
}

static u32
parse_flags(int argc, char** argv) {
    for (int i = 2; i < argc; i++) {
        if (argv[i][0] != '-') return i;

        for (u64 j = 1; argv[i][j]; j++) {
            switch (argv[i][j]) {
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
                default: {
                    dprintf(STDERR_FILENO, "%s: unknown flag: '-%c'\n", progname, argv[i][j]);
                    print_help();
                    exit(EXIT_FAILURE);
                }
            }
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
            bool success = digest(argc, argv, first_input, cmd);
            if (!success) return EXIT_FAILURE;
        } break;
        case CMD_NONE: {
            dprintf(STDERR_FILENO, "Unreachable\n");
            return EXIT_FAILURE;
        } break;
    }
}
