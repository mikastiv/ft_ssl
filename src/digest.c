#include "digest.h"
#include "ssl.h"
#include "types.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern const char* progname;
extern Options options;

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
        case CMD_WHIRLPOOL: {
            name = "WHIRLPOOL";
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

bool
digest(int argc, char** argv, u32 first_input, Command cmd) {
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
        case CMD_WHIRLPOOL: {
            digest_size = WHIRLPOOL_DIGEST_SIZE;
            hasher_fd = &whirlpool_hash_fd;
            hasher_str = &whirlpool_hash_str;
        } break;
        default: {
            dprintf(STDERR_FILENO, "Unreachable\n");
            return false;
        } break;
    }

    u8 buffer[128];
    Buffer out = { .ptr = buffer, .len = digest_size };

    if (options.echo_stdin || first_input == (u32)argc) {
        Buffer input = stdin_to_buffer();
        if (!input.ptr) {
            dprintf(STDERR_FILENO, "%s: %s: %s\n", progname, argv[1], strerror(errno));
        }

        hasher_str(input, out);
        print_hash_stdin(out, input);
        free(input.ptr);
    }

    if (options.first_is_string) {
        Buffer input = str(argv[first_input]);
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

    return true;
}
