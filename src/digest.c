#include "digest.h"
#include "ssl.h"
#include "types.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

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
        bool success = hasher_fd(STDIN_FILENO, options.echo_stdin, out);
        if (success)
            print_hash(out, cmd, false, "stdin");
        else
            dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", progname, argv[1], "stdin", strerror(errno));
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

        bool success = hasher_fd(fd, false, out);
        close(fd);

        if (!success) {
            dprintf(STDERR_FILENO, "%s: %s: %s: %s\n", progname, argv[1], argv[i], strerror(errno));
            continue;
        }

        print_hash(out, cmd, false, argv[i]);
    }

    return true;
}
