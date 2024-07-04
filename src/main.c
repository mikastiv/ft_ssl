#include "cipher.h"
#include "parse.h"
#include "ssl.h"
#include "types.h"
#include "utils.h"

#include <bsd/readpassphrase.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

u32 argc;
const char* const* argv;
const char* progname = 0;

static u64
parse_option_hex(const char* s, const char* name) {
    if (!s) return 0;

    u32 err = 0;
    u64 value = parse_hex_u64_be(str(s), &err);
    if (err) {
        dprintf(STDERR_FILENO, "%s: invalid hex character in %s\n", progname, name);
        exit(EXIT_FAILURE);
    }

    return value;
}

static int
get_infile_fd(const char* filename) {
    int fd = -1;
    if (filename) {
        fd = open(filename, O_RDONLY);
        if (fd < 0) print_error_and_quit();
    } else {
        fd = STDIN_FILENO;
    }

    return fd;
}

static int
get_outfile_fd(const char* filename) {
    int fd = -1;
    if (filename) {
        fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IROTH);
        if (fd < 0) print_error_and_quit();
    } else {
        fd = STDOUT_FILENO;
    }

    return fd;
}

int
main(int in_argc, const char* const* in_argv) {
    argc = in_argc;
    argv = in_argv;

    if (argc > 0) progname = argv[0];
    if (argc < 2) {
        usage();
        return EXIT_FAILURE;
    }

    Command cmd = parse_command(argv[1]);
    if (cmd == Command_None) {
        dprintf(STDERR_FILENO, "%s: unknown command: '%s'\n", progname, argv[1]);
        print_help();
        return EXIT_FAILURE;
    }

    u32 first_input = 2;
    switch (cmd) {
        case Command_Md5:
        case Command_Sha256:
        case Command_Sha224:
        case Command_Sha512:
        case Command_Sha384:
        case Command_Whirlpool: {
            DigestOptions options = { 0 };
            first_input = parse_options(cmd, &options);

            bool success = digest(first_input, cmd, options);
            if (!success) return EXIT_FAILURE;
        } break;
        case Command_Base64: {
            Base64Options options = { 0 };
            first_input = parse_options(cmd, &options);
            if (options.decode && options.encode) {
                dprintf(STDERR_FILENO, "%s: cannot encode and decode at the same time\n", progname);
                exit(EXIT_FAILURE);
            }
            if (!options.decode && !options.encode) options.encode = true;

            int in_fd = get_infile_fd(options.input_file);
            int out_fd = get_outfile_fd(options.output_file);

            Buffer input = read_all_fd(in_fd);
            if (options.input_file) close(in_fd);
            if (!input.ptr) print_error_and_quit();

            Buffer res;
            if (options.decode) {
                res = base64_decode(input);
            } else {
                res = base64_encode(input);
            }

            if (!res.ptr) {
                dprintf(STDERR_FILENO, "%s: invalid input\n", progname);
                exit(EXIT_FAILURE);
            }

            write(out_fd, res.ptr, res.len);
            if (options.encode) write(out_fd, "\n", 1);
            if (options.output_file) close(out_fd);

        } break;
        case Command_Des:
        case Command_DesCbc:
        case Command_DesEcb: {
            DesOptions options = { 0 };
            first_input = parse_options(cmd, &options);

            if (options.decrypt && options.encrypt) {
                dprintf(
                    STDERR_FILENO,
                    "%s: cannot encrypt and decrypt at the same time\n",
                    progname
                );
                exit(EXIT_FAILURE);
            }
            if (!options.decrypt && !options.encrypt) options.encrypt = true;

            int in_fd = get_infile_fd(options.input_file);
            int out_fd = get_outfile_fd(options.output_file);

            DesKey key = { .raw = parse_option_hex(options.hex_key, "key") };
            Des64 salt = { .raw = parse_option_hex(options.hex_salt, "salt") };
            Des64 iv = { .raw = parse_option_hex(options.hex_iv, "iv") };

            if (!options.hex_key) {
                if (!options.password) {
                    char password[64] = { 0 };
                    char verify[64] = { 0 };
                    const char* pass_ptr =
                        readpassphrase("enter password: ", password, sizeof(password), 0);
                    const char* verify_ptr =
                        readpassphrase("reenter password: ", verify, sizeof(verify), 0);

                    if (!pass_ptr || !verify_ptr) {
                        dprintf(STDERR_FILENO, "%s: error reading password\n", progname);
                        exit(EXIT_FAILURE);
                    }

                    if (!ft_memcmp(str(pass_ptr), str(verify_ptr))) {
                        dprintf(STDERR_FILENO, "%s: passwords don't match\n", progname);
                        exit(EXIT_FAILURE);
                    }

                    key = des_pbkdf2_generate(str(pass_ptr), salt);
                } else {
                    key = des_pbkdf2_generate(str(options.password), salt);
                }
            }

            printf("key: ");
            print_hex(key.raw);
            printf("salt: ");
            print_hex(salt.raw);
            printf("iv: ");
            print_hex(iv.raw);

            Buffer input = read_all_fd(in_fd);
            if (options.input_file) close(in_fd);
            if (!input.ptr) print_error_and_quit();

            if (options.decrypt && options.use_base64) {
                Buffer tmp = base64_decode(input);
                if (!tmp.ptr) {
                    dprintf(STDERR_FILENO, "%s: invalid base64 input\n", progname);
                    exit(EXIT_FAILURE);
                }
                free(input.ptr);
                input = tmp;
            }

            Buffer res;
            switch (cmd) {
                case Command_DesEcb: {
                    if (options.encrypt) {
                        res = des_ecb_encrypt(input, key);
                    } else {
                        res = des_ecb_decrypt(input, key);
                    }
                } break;
                case Command_Des:
                case Command_DesCbc: {
                    if (!options.hex_iv) {
                        dprintf(
                            STDERR_FILENO,
                            "%s: initialization vector is required for cbc mode\n",
                            progname
                        );
                        exit(EXIT_FAILURE);
                    }

                    if (options.encrypt) {
                        res = des_cbc_encrypt(input, key, iv);
                    } else {
                        res = des_cbc_decrypt(input, key, iv);
                    }
                } break;
                default: {
                    dprintf(STDERR_FILENO, "unreachable code\n");
                    exit(EXIT_FAILURE);
                } break;
            }

            if (options.encrypt && options.use_base64) {
                Buffer tmp = base64_encode(res);
                if (!tmp.ptr) {
                    dprintf(STDERR_FILENO, "%s: out of memory\n", progname);
                    exit(EXIT_FAILURE);
                }
                free(res.ptr);
                res = tmp;
            }

            write(out_fd, res.ptr, res.len);
            if (options.encrypt && options.use_base64) write(out_fd, "\n", 1);
            if (options.output_file) close(out_fd);

        } break;
        case Command_None: {
            dprintf(STDERR_FILENO, "Unreachable\n");
            return EXIT_FAILURE;
        } break;
    }
}
