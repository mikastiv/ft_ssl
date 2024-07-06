#include "cipher.h"
#include "parse.h"
#include "ssl.h"
#include "types.h"
#include "utils.h"

#include <assert.h>
#include <bsd/readpassphrase.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

u32 argc;
const char* const* argv;
const char* progname = 0;

static void
parse_option_hex(const char* s, const char* name, Buffer out, u32* err) {
    if (!s) return;

    *err = 0;
    parse_hex(str(s), out, err);
    if (*err) {
        dprintf(STDERR_FILENO, "%s: invalid hex character in %s\n", progname, name);
        return;
    }
}

static int
get_infile_fd(const char* filename) {
    int fd = -1;
    if (filename) {
        fd = open(filename, O_RDONLY);
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

            if (in_fd == -1 || out_fd == -1) {
                print_error();
                goto base64_err;
            }

            Buffer input = read_all_fd(in_fd);
            if (!input.ptr) {
                print_error();
                goto base64_err;
            }

            Buffer res;
            if (options.decode) {
                res = base64_decode(input);
            } else {
                res = base64_encode(input);
            }

            if (!res.ptr) {
                dprintf(STDERR_FILENO, "%s: invalid input\n", progname);
                goto base64_err;
            }

            write(out_fd, res.ptr, res.len);
            if (options.encode) write(out_fd, "\n", 1);
            goto base64_cleanup;

        base64_err:
            if (options.output_file && out_fd != -1) close(out_fd);
            if (options.input_file && in_fd != -1) close(in_fd);
            exit(EXIT_FAILURE);

        base64_cleanup:
            if (options.output_file && out_fd != -1) close(out_fd);
            if (options.input_file && in_fd != -1) close(in_fd);
            free(res.ptr);

        } break;
        case Command_Des:
        case Command_DesCbc:
        case Command_DesEcb:
        case Command_Des3:
        case Command_Des3Cbc:
        case Command_Des3Ecb: {
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

            if (in_fd == -1 || out_fd == -1) {
                print_error();
                goto des_err;
            }

            switch (cmd) {
                case Command_Des:
                case Command_DesCbc:
                case Command_Des3:
                case Command_Des3Cbc: {
                    if (!options.hex_iv) {
                        dprintf(
                            STDERR_FILENO,
                            "%s: initialization vector is required for cbc mode\n",
                            progname
                        );
                        goto des_err;
                    }
                } break;
                default:
                    break;
            }

            u64 params_len = 0;
            switch (cmd) {
                case Command_Des:
                case Command_DesCbc:
                case Command_DesEcb: {
                    params_len = 8;
                } break;
                case Command_Des3:
                case Command_Des3Cbc:
                case Command_Des3Ecb: {
                    params_len = 24;
                } break;
                default:
                    break;
            }

            u32 err1 = 0;
            u32 err2 = 0;
            u32 err3 = 0;
            u8 salt[64] = { 0 };
            u8 key[64] = { 0 };
            u8 iv[64] = { 0 };
            parse_option_hex(options.hex_salt, "salt", buffer_create(salt, params_len), &err1);
            parse_option_hex(options.hex_key, "key", buffer_create(key, params_len), &err2);
            parse_option_hex(options.hex_iv, "iv", buffer_create(iv, params_len), &err3);

            if (err1 || err2 || err3) {
                goto des_err;
            }

            if (!options.hex_key) {
                if (!options.hex_salt) {
                    if (options.decrypt) {
                        dprintf(STDERR_FILENO, "%s: provide salt when decrypting\n", progname);
                        goto des_err;
                    }

                    bool success = get_random_bytes(buffer_create(salt, params_len));
                    if (!success) {
                        dprintf(STDERR_FILENO, "%s: error generating salt\n", progname);
                        goto des_err;
                    }
                }

                if (!options.password) {
                    char password[64] = { 0 };
                    char verify[64] = { 0 };
                    const char* pass_ptr =
                        readpassphrase("enter password: ", password, sizeof(password), 0);
                    const char* verify_ptr =
                        readpassphrase("reenter password: ", verify, sizeof(verify), 0);

                    if (!pass_ptr || !verify_ptr) {
                        dprintf(STDERR_FILENO, "%s: error reading password\n", progname);
                        goto des_err;
                    }

                    if (!ft_memcmp(str(pass_ptr), str(verify_ptr))) {
                        dprintf(STDERR_FILENO, "%s: passwords don't match\n", progname);
                        goto des_err;
                    }

                    pbkdf2_generate(
                        str(pass_ptr),
                        buffer_create(salt, params_len),
                        buffer_create(key, params_len)
                    );
                } else {
                    pbkdf2_generate(
                        str(options.password),
                        buffer_create(salt, params_len),
                        buffer_create(key, params_len)
                    );
                }

                printf("salt=");
                print_hex(buffer_create(salt, params_len));
                printf("key=");
                print_hex(buffer_create(key, params_len));
            }

            Buffer input = read_all_fd(in_fd);
            if (!input.ptr) {
                print_error();
                goto des_err;
            }

            if (options.decrypt && options.use_base64) {
                Buffer tmp = base64_decode(input);
                if (!tmp.ptr) {
                    dprintf(STDERR_FILENO, "%s: invalid base64 input\n", progname);
                    free(input.ptr);
                    goto des_err;
                }
                free(input.ptr);
                input = tmp;
            }

            Buffer res;
            switch (cmd) {
                case Command_DesEcb: {
                    assert(params_len == 8);

                    DesKey des_key;
                    ft_memcpy(
                        buffer_create(des_key.block, params_len),
                        buffer_create(key, params_len)
                    );

                    if (options.encrypt) {
                        res = des_ecb_encrypt(input, des_key);
                    } else {
                        res = des_ecb_decrypt(input, des_key);
                    }
                } break;
                case Command_Des:
                case Command_DesCbc: {
                    assert(params_len == 8);

                    DesKey des_key;
                    ft_memcpy(
                        buffer_create(des_key.block, params_len),
                        buffer_create(key, params_len)
                    );

                    Des64 des_iv;
                    ft_memcpy(
                        buffer_create(des_iv.block, params_len),
                        buffer_create(iv, params_len)
                    );

                    if (options.encrypt) {
                        res = des_cbc_encrypt(input, des_key, des_iv);
                    } else {
                        res = des_cbc_decrypt(input, des_key, des_iv);
                    }
                } break;
                case Command_Des3Ecb: {
                } break;
                case Command_Des3:
                case Command_Des3Cbc: {
                } break;
                default: {
                    dprintf(STDERR_FILENO, "unreachable code\n");
                    exit(EXIT_FAILURE);
                } break;
            }

            if (!res.ptr) {
                goto des_err;
            }

            if (options.encrypt && options.use_base64) {
                Buffer tmp = base64_encode(res);
                if (!tmp.ptr) {
                    dprintf(STDERR_FILENO, "%s: failed to base64 encode\n", progname);
                    goto des_err;
                }
                free(res.ptr);
                res = tmp;
            }

            write(out_fd, res.ptr, res.len);
            if (options.encrypt && options.use_base64) write(out_fd, "\n", 1);
            goto des_cleanup;

        des_err:
            if (options.output_file && out_fd != -1) close(out_fd);
            if (options.input_file && in_fd != -1) close(in_fd);
            exit(EXIT_FAILURE);

        des_cleanup:
            if (options.output_file && out_fd != -1) close(out_fd);
            if (options.input_file && in_fd != -1) close(in_fd);
            free(res.ptr);

        } break;
        case Command_None: {
            dprintf(STDERR_FILENO, "Unreachable\n");
            return EXIT_FAILURE;
        } break;
    }
}
