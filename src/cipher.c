#include "cipher.h"
#include "globals.h"
#include "ssl.h"
#include "utils.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

static DesFunc
fetch_des_func(bool encrypt, Command cmd) {
    DesFunc result = 0;
    switch (cmd) {
        case Command_DesEcb: {
            if (encrypt)
                result = &des_ecb_encrypt;
            else
                result = &des_ecb_decrypt;
        } break;
        case Command_Des:
        case Command_DesCbc: {
            if (encrypt)
                result = &des_cbc_encrypt;
            else
                result = &des_cbc_decrypt;
        } break;
        case Command_DesOfb: {
            if (encrypt)
                result = &des_ofb_encrypt;
            else
                result = &des_ofb_decrypt;
        } break;
        case Command_DesCfb: {
            if (encrypt)
                result = &des_cfb_encrypt;
            else
                result = &des_cfb_decrypt;
        } break;
        case Command_DesPcbc: {
            if (encrypt)
                result = &des_pcbc_encrypt;
            else
                result = &des_pcbc_decrypt;
        } break;
        case Command_Des3Ecb: {
            if (encrypt)
                result = &des3_ecb_encrypt;
            else
                result = &des3_ecb_decrypt;
        } break;
        case Command_Des3:
        case Command_Des3Cbc: {
            if (encrypt)
                result = &des3_cbc_encrypt;
            else
                result = &des3_cbc_decrypt;
        } break;
        case Command_Des3Ofb: {
            if (encrypt)
                result = &des3_ofb_encrypt;
            else
                result = &des3_ofb_decrypt;
        } break;
        case Command_Des3Cfb: {
            if (encrypt)
                result = &des3_cfb_encrypt;
            else
                result = &des3_cfb_decrypt;
        } break;
        case Command_Des3Pcbc: {
            if (encrypt)
                result = &des3_pcbc_encrypt;
            else
                result = &des3_pcbc_decrypt;
        } break;
        default:
            assert(false && "unreachable code");
            break;
    }

    return result;
}

static bool
des_requires_iv(Command cmd) {
    return cmd != Command_DesEcb && cmd != Command_Des3Ecb;
}

static u64
get_params_length(Command cmd) {
    u64 params_len = 0;
    switch (cmd) {
        case Command_Des:
        case Command_DesCbc:
        case Command_DesOfb:
        case Command_DesCfb:
        case Command_DesPcbc:
        case Command_DesEcb: {
            params_len = DES_BLOCK_SIZE;
        } break;
        case Command_Des3:
        case Command_Des3Cbc:
        case Command_Des3Ofb:
        case Command_Des3Cfb:
        case Command_Des3Pcbc:
        case Command_Des3Ecb: {
            params_len = DES_BLOCK_SIZE * 3;
        } break;
        default:
            break;
    }

    return params_len;
}

bool
cipher(Command cmd, DesOptions* options) {
    if (options->decrypt && options->encrypt) {
        dprintf(STDERR_FILENO, "%s: cannot encrypt and decrypt at the same time\n", progname);
        exit(EXIT_FAILURE);
    }
    if (!options->decrypt && !options->encrypt) options->encrypt = true;

    int in_fd = get_infile_fd(options->input_file);
    int out_fd = get_outfile_fd(options->output_file);

    if (in_fd == -1 || out_fd == -1) {
        print_error();
        goto des_err;
    }

    if (des_requires_iv(cmd) && !options->hex_iv) {
        dprintf(STDERR_FILENO, "%s: initialization vector is required for cbc mode\n", progname);
        goto des_err;
    }

    u64 params_len = get_params_length(cmd);

    u32 err1 = 0;
    u32 err2 = 0;
    u32 err3 = 0;
    u8 salt[64] = { 0 };
    u8 key[64] = { 0 };
    u8 iv[DES_BLOCK_SIZE] = { 0 };
    parse_option_hex(options->hex_salt, "salt", buf(salt, params_len), &err1);
    parse_option_hex(options->hex_key, "key", buf(key, params_len), &err2);
    parse_option_hex(options->hex_iv, "iv", buf(iv, DES_BLOCK_SIZE), &err3);

    if (err1 || err2 || err3) {
        goto des_err;
    }

    if (!options->hex_key) {
        if (!options->hex_salt) {
            if (options->decrypt) {
                dprintf(STDERR_FILENO, "%s: provide salt when decrypting\n", progname);
                goto des_err;
            }

            bool success = get_random_bytes(buf(salt, params_len));
            if (!success) {
                dprintf(STDERR_FILENO, "%s: error generating salt\n", progname);
                goto des_err;
            }
        }

        char password[MAX_PASSWORD_SIZE];
        if (!options->password) {
            if (!read_password(buf((u8*)password, MAX_PASSWORD_SIZE))) {
                goto des_err;
            }

            options->password = password;
        }

        pbkdf2_generate(str(options->password), buf(salt, params_len), buf(key, params_len));

        printf("salt=");
        print_hex(buf(salt, params_len));
        printf("key=");
        print_hex(buf(key, params_len));
    }

    Buffer input = read_all_fd(in_fd);
    if (!input.ptr) {
        print_error();
        goto des_err;
    }

    if (options->decrypt && options->use_base64) {
        Buffer tmp = base64_decode(input);
        if (!tmp.ptr) {
            dprintf(STDERR_FILENO, "%s: invalid base64 input\n", progname);
            free(input.ptr);
            goto des_err;
        }
        free(input.ptr);
        input = tmp;
    }

    assert(params_len == get_params_length(cmd));

    Des64 des_iv;
    ft_memcpy(buf(des_iv.block, DES_BLOCK_SIZE), buf(iv, DES_BLOCK_SIZE));

    DesFunc func = fetch_des_func(options->encrypt, cmd);
    Buffer res = func(input, buf(key, params_len), des_iv);

    if (!res.ptr) {
        goto des_err;
    }

    if (options->encrypt && options->use_base64) {
        Buffer tmp = base64_encode(res);
        if (!tmp.ptr) {
            dprintf(STDERR_FILENO, "%s: failed to base64 encode\n", progname);
            goto des_err;
        }
        free(res.ptr);
        res = tmp;
    }

    write(out_fd, res.ptr, res.len);
    if (options->encrypt && options->use_base64) write(out_fd, "\n", 1);
    if (options->output_file && out_fd != -1) close(out_fd);
    if (options->input_file && in_fd != -1) close(in_fd);
    free(res.ptr);
    return EXIT_SUCCESS;

des_err:
    if (options->output_file && out_fd != -1) close(out_fd);
    if (options->input_file && in_fd != -1) close(in_fd);
    return EXIT_FAILURE;
}
