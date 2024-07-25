#include "arena.h"
#include "bignum.h"
#include "cipher.h"
#include "parse.h"
#include "ssl.h"
#include "standard.h"
#include "types.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

u32 argc;
const char* const* argv;
const char* progname = 0;
Arena arena;

int
main(int in_argc, const char* const* in_argv) {
    argc = in_argc;
    argv = in_argv;

    if (argc > 0) progname = argv[0];
    if (argc < 2) {
        usage(0);
        return EXIT_FAILURE;
    }

    Command cmd = parse_command(argv[1]);
    if (cmd == Command_None) {
        if (ft_strcmp(argv[1], "-h") != 0) {
            dprintf(STDERR_FILENO, "%s: unknown command: '%s'\n", progname, argv[1]);
        }
        print_help(cmd);
        return EXIT_FAILURE;
    }

    if (!arena_init(&arena, MAX_MEMORY)) {
        dprintf(STDERR_FILENO, "%s: failed to allocate memory\n", progname);
        return EXIT_FAILURE;
    }

    genrsa();

    int result = EXIT_SUCCESS;
    switch (cmd) {
        case Command_Md5:
        case Command_Sha256:
        case Command_Sha224:
        case Command_Sha512:
        case Command_Sha384:
        case Command_Whirlpool: {
            DigestOptions options = { 0 };
            u32 first_input = parse_options(cmd, &options);

            bool success = digest(first_input, cmd, options);
            if (!success) result = EXIT_FAILURE;
        } break;
        case Command_Base64: {
            Base64Options options = { 0 };
            parse_options(cmd, &options);

            bool success = base64(&options);
            if (!success) result = EXIT_FAILURE;
        } break;
        case Command_Des:
        case Command_DesCbc:
        case Command_DesEcb:
        case Command_DesOfb:
        case Command_DesCfb:
        case Command_DesPcbc:
        case Command_Des3:
        case Command_Des3Cbc:
        case Command_Des3Ofb:
        case Command_Des3Cfb:
        case Command_Des3Pcbc:
        case Command_Des3Ecb: {
            DesOptions options = { 0 };
            parse_options(cmd, &options);

            bool success = cipher(cmd, &options);
            if (!success) result = EXIT_FAILURE;
        } break;
        case Command_None: {
            dprintf(STDERR_FILENO, "Unreachable\n");
            result = EXIT_FAILURE;
        } break;
    }

    arena_log_watermark(&arena);
    arena_free(&arena);

    return result;
}
