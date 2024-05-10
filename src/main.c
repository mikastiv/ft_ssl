#include "hash.h"
#include "ssl.h"
#include "types.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const char* progname;
static Options options;

const char* cmd_names[] = {
    [CMD_NONE] = "none",
    [CMD_MD5] = "md5",
    [CMD_SHA256] = "sha256",
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
    print_flag('p', "echo STDIN to STDOUT and append the checksum to STDOUT");
    print_flag('q', "quiet mode");
    print_flag('r', "reverse the format of the output");
    print_flag('s', "print the sum of the given string");
}

static u64
parse_flags(int argc, char** argv) {
    for (int i = 2; i < argc; i++) {
        if (argv[i][0] != '-') return i;

        u64 len = ft_strlen(argv[i]);
        for (u64 j = 1; j < len; j++) {
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
                    options.print_sum = true;
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

    u64 first_input = 3;
    if (argc > 2) {
        first_input = parse_flags(argc, argv);
    }
    (void)first_input;

    u8 buffer[16];
    Buffer out = { .ptr = buffer, .len = 16 };
    Md5 md5 = md5_init();
    md5_update(
        &md5,
        str("An MD5 hash is created by taking a string of an any length and encoding it into a "
            "128-bit fingerprint. Encoding the same string using the MD5 algorithm will always "
            "result in the same 128-bit hash output.")
    );
    md5_update(
        &md5,
        str(" MD5 hashes are commonly used with smaller "
            "strings when storing passwords, credit card numbers or other sensitive data in "
            "databases such as the popular MySQL. This tool provides a quick and easy way to "
            "encode an MD5 hash from a simple string of up to 256 characters in length.")
    );
    md5_final(&md5, out);

    for (u32 i = 0; i < 16; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}
