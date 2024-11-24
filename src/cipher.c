#include "cipher.h"
#include "globals.h"
#include "ssl.h"
#include "utils.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static void
parse_option_hex(const char* s, const char* name, Buffer out, bool* err) {
    if (!s) return;

    *err = false;
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
get_key_length(Command cmd) {
    u64 key_len = 0;
    switch (cmd) {
        case Command_Des:
        case Command_DesCbc:
        case Command_DesOfb:
        case Command_DesCfb:
        case Command_DesPcbc:
        case Command_DesEcb: {
            key_len = DES_KEY_SIZE;
        } break;
        case Command_Des3:
        case Command_Des3Cbc:
        case Command_Des3Ofb:
        case Command_Des3Cfb:
        case Command_Des3Pcbc:
        case Command_Des3Ecb: {
            key_len = DES_KEY_SIZE * 3;
        } break;
        default:
            break;
    }

    return key_len;
}

static const char*
get_cipher_mode_name(Command cmd) {
    const char* mode = 0;

    switch (cmd) {
        case Command_Des:
        case Command_DesCbc:
        case Command_Des3:
        case Command_Des3Cbc: {
            mode = "cbc";
        } break;
        case Command_DesEcb:
        case Command_Des3Ecb: {
            mode = "ecb";
        } break;
        case Command_DesCfb:
        case Command_Des3Cfb: {
            mode = "cfb";
        } break;
        case Command_DesOfb:
        case Command_Des3Ofb: {
            mode = "ofb";
        } break;
        case Command_DesPcbc:
        case Command_Des3Pcbc: {
            mode = "pcbc";
        } break;
        default: {
            assert(false && "unreachable code");
        } break;
    }

    return mode;
}

bool
cipher(Command cmd, DesOptions* options) {
    bool result = false;

    if (options->decrypt && options->encrypt) {
        dprintf(STDERR_FILENO, "%s: cannot encrypt and decrypt at the same time\n", progname);
        return false;
    }
    if (!options->decrypt && !options->encrypt) options->encrypt = true;

    int in_fd = get_infile_fd(options->input_file);
    int out_fd = get_outfile_fd(options->output_file);

    if (in_fd == -1 || out_fd == -1) {
        print_error();
        goto cipher_err;
    }

    u64 keylen = get_key_length(cmd);

    bool err1 = 0;
    bool err2 = 0;
    bool err3 = 0;
    u8 salt[PBKDF2_SALT_SIZE + 1] = { 0 };
    // iv is at the end of key when using pbkdf2
    u8 key[PBKDF2_MAX_KEY_SIZE + DES_BLOCK_SIZE] = { 0 };
    u8 iv[DES_BLOCK_SIZE] = { 0 };
    parse_option_hex(options->hex_salt, "salt", buf(salt, PBKDF2_SALT_SIZE), &err1);
    parse_option_hex(options->hex_key, "key", buf(key, keylen), &err2);
    parse_option_hex(options->hex_iv, "iv", buf(iv, DES_BLOCK_SIZE), &err3);

    if (err1 || err2 || err3) {
        goto cipher_err;
    }

    u64 size_hint = get_filesize(in_fd);
    Buffer input = read_all_fd(in_fd, size_hint);
    if (!input.ptr) {
        print_error();
        goto cipher_err;
    }

    if (options->decrypt && options->use_base64) {
        input = base64_decode(input);
        if (!input.ptr) {
            dprintf(STDERR_FILENO, "%s: invalid base64 input\n", progname);
            goto cipher_err;
        }
    }

    bool generate_salt = !options->hex_salt;

    const Buffer magic = str("Salted__");
    if (ft_memcmp(buf(input.ptr, magic.len), magic)) {
        generate_salt = false;
        input.ptr += magic.len;
        ft_memcpy(buf(salt, PBKDF2_SALT_SIZE), buf(input.ptr, PBKDF2_SALT_SIZE));
        input.ptr += PBKDF2_SALT_SIZE;
        input.len -= magic.len + PBKDF2_SALT_SIZE;
    }

    if (!options->hex_key) {
        if (generate_salt) {
            if (options->decrypt) {
                dprintf(STDERR_FILENO, "%s: provide salt when decrypting\n", progname);
                goto cipher_err;
            }

            bool success = get_random_bytes(buf(salt, PBKDF2_SALT_SIZE));
            if (!success) {
                dprintf(STDERR_FILENO, "%s: error generating salt\n", progname);
                goto cipher_err;
            }
        }

        char password[MAX_PASSWORD_SIZE];
        if (!options->password) {
            if (!read_password(buf((u8*)password, MAX_PASSWORD_SIZE), options->encrypt)) {
                goto cipher_err;
            }

            options->password = password;
        }

        u64 ivlen = 0;
        if (!options->hex_iv && des_requires_iv(cmd)) {
            ivlen = DES_BLOCK_SIZE;
        }

        pbkdf2_generate(str(options->password), buf(salt, PBKDF2_SALT_SIZE), 10000, buf(key, keylen + ivlen));

        if (ivlen) {
            ft_memcpy(buf(iv, DES_BLOCK_SIZE), buf(key + keylen, DES_BLOCK_SIZE));
        }

        if (options->encrypt) {
            dprintf(STDERR_FILENO, "salt=");
            print_hex(buf(salt, PBKDF2_SALT_SIZE));
            dprintf(STDERR_FILENO, "key=");
            print_hex(buf(key, keylen));
            if (des_requires_iv(cmd)) {
                dprintf(STDERR_FILENO, "iv=");
                print_hex(buf(iv, DES_BLOCK_SIZE));
            }
        }
    } else if (des_requires_iv(cmd) && !options->hex_iv) {
        const char* mode = get_cipher_mode_name(cmd);
        dprintf(STDERR_FILENO, "%s: initialization vector is required for %s mode\n", progname, mode);
        goto cipher_err;
    }

    Des64 des_iv;
    ft_memcpy(buf(des_iv.block, DES_BLOCK_SIZE), buf(iv, DES_BLOCK_SIZE));

    assert(keylen == get_key_length(cmd));

    DesFunc func = fetch_des_func(options->encrypt, cmd);
    Buffer res = func(input, buf(key, keylen), des_iv);

    if (!res.ptr) {
        goto cipher_err;
    }

    if (!options->hex_key && generate_salt) {
        u64 newsize = res.len + magic.len + DES_BLOCK_SIZE;
        Buffer tmp = { .ptr = arena_alloc(&arena, newsize), .len = newsize };
        ft_memcpy(buf(tmp.ptr, magic.len), magic);
        ft_memcpy(buf(tmp.ptr + magic.len, DES_BLOCK_SIZE), buf(salt, DES_BLOCK_SIZE));
        ft_memcpy(buf(tmp.ptr + magic.len + DES_BLOCK_SIZE, res.len), res);
        res = tmp;
    }

    if (options->encrypt && options->use_base64) {
        res = base64_encode(res);
        if (!res.ptr) {
            dprintf(STDERR_FILENO, "%s: failed to base64 encode\n", progname);
            goto cipher_err;
        }
    }

    (void)write(out_fd, res.ptr, res.len);
    if (options->encrypt && options->use_base64) (void)write(out_fd, "\n", 1);

    result = true;

cipher_err:
    if (options->output_file && out_fd != -1) close(out_fd);
    if (options->input_file && in_fd != -1) close(in_fd);
    return result;
}
