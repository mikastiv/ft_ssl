#include "hash.h"
#include "ssl.h"
#include "types.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const char* progname;
static Options options;

static int
parse_flags(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') return i;

        const u64 len = ft_strlen(argv[i]);
        for (int j = 1; j < len; j++) {
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
            }
        }
    }
    return argc;
}

int
main(int argc, char** argv) {
    if (argc > 0) progname = argv[0];
    if (argc < 2) {
        dprintf(STDERR_FILENO, "usage: %s command [flags] [file/string]\n", progname);
        return EXIT_FAILURE;
    }
}
