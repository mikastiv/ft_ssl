#include "hash.h"

Md5
md5_init() {
    Md5 md5 = {
        .state = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 },
        .total_len = 0,
    };

    return md5;
}

void
md5_update(Md5* md5, Buffer buffer) {
}

void
md5_end(Md5* md5, Buffer out) {
}
