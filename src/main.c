#include "hash.h"
#include "ssl.h"
#include "types.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char* progname;
static Options options;

const char* cmd_names[] = {
    [CMD_NONE] = "none",     [CMD_MD5] = "md5",       [CMD_SHA256] = "sha256",
    [CMD_SHA224] = "sha224", [CMD_SHA512] = "sha512", [CMD_SHA384] = "sha384",
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

static void
print_hash(Buffer hash, Command cmd, bool is_str, const char* input) {
    const char* name;
    switch (cmd) {
        case CMD_MD5: {
            name = "MD5";
        } break;
        case CMD_SHA256: {
            name = "SHA256";
        } break;
        case CMD_SHA224: {
            name = "SHA224";
        } break;
        case CMD_SHA512: {
            name = "SHA512";
        } break;
        case CMD_SHA384: {
            name = "SHA384";
        } break;
        case CMD_NONE: {
            name = "Unknown";
        } break;
    }

    if (!options.quiet && !options.reverse_fmt) {
        printf("%s (", name);
        if (is_str) printf("\"");
        printf("%s", input);
        if (is_str) printf("\"");
        printf(") = ");
    }

    for (u64 i = 0; i < hash.len; i++) {
        printf("%02x", hash.ptr[i]);
    }

    if (!options.quiet && options.reverse_fmt) {
        printf(" ");
        if (is_str) printf("\"");
        printf("%s", input);
        if (is_str) printf("\"");
    }

    printf("\n");
}

static void
print_hash_stdin(Buffer hash, Buffer input) {
    bool newline = input.len && input.ptr[input.len - 1] == '\n';
    const char* label = options.echo_stdin ? (char*)input.ptr : "stdin";

    // Remove last newline
    if (newline) input.ptr[input.len - 1] = 0;

    if (options.quiet && options.echo_stdin) {
        printf("%s\n", input.ptr);
    } else if (!options.quiet) {
        printf("(");
        if (options.echo_stdin) printf("\"");
        printf("%s", label);
        if (options.echo_stdin) printf("\"");
        printf(")= ");
    }

    for (u64 i = 0; i < hash.len; i++) {
        printf("%02x", hash.ptr[i]);
    }
    printf("\n");

    // Restore newline
    if (newline) input.ptr[input.len - 1] = '\n';
}

static Buffer
stdin_to_buffer(void) {
    u64 capacity = 2048;
    Buffer str = { .ptr = malloc(capacity + 1), .len = 0 };
    if (!str.ptr) return (Buffer){ 0 };

    u8 buffer[2048];
    i64 bytes = sizeof(buffer);
    while (bytes > 0) {
        bytes = read(STDIN_FILENO, buffer, sizeof(buffer));
        if (bytes < 0) return (Buffer){ 0 };

        u64 remaining = capacity - str.len;

        if ((u64)bytes > remaining) {
            u64 rest = bytes - remaining;
            capacity = (capacity * 2 > rest) ? capacity * 2 : rest;

            u8* ptr = malloc(capacity + 1);
            if (!ptr) return (Buffer){ 0 };

            ft_memcpy(buffer_create(ptr, str.len), str);
            free(str.ptr);
            str.ptr = ptr;
        }

        ft_memcpy(buffer_create(str.ptr + str.len, bytes), buffer_create(buffer, bytes));
        str.len += bytes;
    }

    str.ptr[str.len] = 0;

    return str;
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

    u64 first_input = 2;
    if (argc > 2) {
        first_input = parse_flags(argc, argv);
    }

    if (options.print_help) {
        print_help();
        return EXIT_FAILURE;
    }

    u64 digest_size;
    HasherFd hasher_fd;
    HasherStr hasher_str;
    switch (cmd) {
        case CMD_MD5: {
            digest_size = MD5_DIGEST_SIZE;
            hasher_fd = &md5_hash_fd;
            hasher_str = &md5_hash_str;
        } break;
        case CMD_SHA256: {
            digest_size = SHA256_DIGEST_SIZE;
            hasher_fd = &sha256_hash_fd;
            hasher_str = &sha256_hash_str;
        } break;
        case CMD_SHA224: {
            digest_size = SHA224_DIGEST_SIZE;
            hasher_fd = &sha224_hash_fd;
            hasher_str = &sha224_hash_str;
        } break;
        case CMD_SHA512: {
            digest_size = SHA512_DIGEST_SIZE;
            hasher_fd = &sha512_hash_fd;
            hasher_str = &sha512_hash_str;
        } break;
        case CMD_SHA384: {
            digest_size = SHA384_DIGEST_SIZE;
            hasher_fd = &sha384_hash_fd;
            hasher_str = &sha384_hash_str;
        } break;
        case CMD_NONE: {
            return EXIT_FAILURE;
        } break;
    }

    u8 buffer[64];
    Buffer out = { .ptr = buffer, .len = digest_size };

    if (options.echo_stdin || first_input == (u64)argc) {
        Buffer input = stdin_to_buffer();
        if (!input.ptr) {
            dprintf(STDERR_FILENO, "%s: %s: %s\n", progname, argv[1], strerror(errno));
        }

        hasher_str(input, out);
        print_hash_stdin(out, input);
        free(input.ptr);
    }

    if (options.first_is_string) {
        Buffer input = {
            .ptr = (u8*)argv[first_input],
            .len = ft_strlen(argv[first_input]),
        };
        hasher_str(input, out);

        print_hash(out, cmd, true, argv[first_input]);

        first_input++;
    }

    for (u64 i = first_input; i < (u64)argc; i++) {
        int fd = open(argv[i], O_RDONLY);
        if (fd < 0) {
            dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", progname, argv[1], argv[i], strerror(errno));
            continue;
        }

        bool success = hasher_fd(fd, out);
        close(fd);

        if (!success) {
            dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", progname, argv[1], argv[i], strerror(errno));
            continue;
        }

        print_hash(out, cmd, false, argv[i]);
    }
}
