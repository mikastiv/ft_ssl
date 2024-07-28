#include "asn1.h"
#include "utils.h"
#include <assert.h>

AsnSeq
asn_seq_init(void) {
    return (AsnSeq){ 0 };
}

static void
asn_seq_write_byte(AsnSeq* seq, u8 byte) {
    assert(seq->len < ASN_SEQ_MAXSIZE);

    seq->buffer[seq->len++] = byte;
}

static bool
asn_read_length(Buffer input, u64* index, u64* len) {
    if (*index >= input.len) return false;

    AsnLength asn_len = { .raw = input.ptr[(*index)++] };
    if (asn_len.more) {
        u64 bytes = asn_len.length;
        if (bytes != 2) return false; // Not supporting more than 2 bytes length

        *len = 0;
        if (*index >= input.len) return false;
        *len = (u64)input.ptr[(*index)++] << 8;

        if (*index >= input.len) return false;
        *len |= (u64)input.ptr[(*index)++];
    } else {
        *len = asn_len.length;
    }

    return true;
}

static void
asn_seq_write_length(AsnSeq* seq, u64 len) {
    assert(len < UINT16_MAX);

    AsnLength asn_len = { 0 };
    if (len > 127) {
        asn_len.more = 1;
        asn_len.length = 2;

        asn_seq_write_byte(seq, asn_len.raw);
        asn_seq_write_byte(seq, (u8)(len >> 8));
        asn_seq_write_byte(seq, (u8)len);
    } else {
        asn_len.length = (u8)len;
        asn_seq_write_byte(seq, asn_len.raw);
    }
}

void
asn_seq_add_integer(AsnSeq* seq, u64 value, u64 bitsize) {
    AsnOctet1 oct1 = { 0 };
    oct1.tag_type = AsnInteger;

    u8 len = 1;
    if (value > 0xFF) len++;
    if (value > 0xFFFF) len++;
    if (value > 0xFFFFFF) len++;
    if (value > 0xFFFFFFFF) len++;
    if (value > 0xFFFFFFFFFF) len++;
    if (value > 0xFFFFFFFFFFFF) len++;
    if (value > 0xFFFFFFFFFFFFFF) len++;

    if (value & (1ull << (bitsize - 1))) {
        len++;
    }

    asn_seq_write_byte(seq, oct1.raw);
    asn_seq_write_byte(seq, len);

    if (value & (1ull << (bitsize - 1))) {
        asn_seq_write_byte(seq, 0);
    }

    if (value == 0) {
        asn_seq_write_byte(seq, 0);
        return;
    }

    value = byte_swap64(value);
    while ((value & 0xFF) == 0) {
        value >>= 8;
    }

    while (true) {
        asn_seq_write_byte(seq, (u8)value);
        value >>= 8;
        if (!value) break;
    }
}

void
asn_seq_add_null(AsnSeq* seq, u8 value) {
    AsnOctet1 oct1 = { 0 };
    oct1.tag_type = AsnNull;

    asn_seq_write_byte(seq, oct1.raw);
    asn_seq_write_byte(seq, value);
}

void
asn_seq_add_object_ident(AsnSeq* seq, Buffer value) {
    AsnOctet1 oct1 = { 0 };
    oct1.tag_type = AsnObjectIdentifier;

    u64 len = value.len;

    asn_seq_write_byte(seq, oct1.raw);
    asn_seq_write_length(seq, len);

    for (u64 i = 0; i < value.len; i++) {
        asn_seq_write_byte(seq, value.ptr[i]);
    }
}

void
asn_seq_add_octet_str_seq(AsnSeq* seq, AsnSeq* value) {
    AsnOctet1 oct1 = { 0 };
    oct1.tag_type = AsnOctetString;

    u64 octet_str_len = value->len;
    if (octet_str_len > 127) octet_str_len += 2; // seq long form length
    octet_str_len += 2;                          // seq length + tag octet

    asn_seq_write_byte(seq, oct1.raw);
    asn_seq_write_length(seq, octet_str_len);

    asn_seq_add_seq(seq, value);
}

void
asn_seq_add_bit_str_seq(AsnSeq* seq, AsnSeq* value) {
    AsnOctet1 oct1 = { 0 };
    oct1.tag_type = AsnBitString;

    u64 bit_str_len = value->len;
    if (bit_str_len > 127) bit_str_len += 2; // seq long form length
    bit_str_len += 3;                        // seq length + tag octet + unused bits

    asn_seq_write_byte(seq, oct1.raw);
    asn_seq_write_length(seq, bit_str_len);
    asn_seq_write_byte(seq, 0); // unused bits

    asn_seq_add_seq(seq, value);
}

void
asn_seq_add_seq(AsnSeq* parent, AsnSeq* seq) {
    AsnOctet1 oct1 = { 0 };
    oct1.tag_type = AsnSequence;
    oct1.pc = 1;

    asn_seq_write_byte(parent, oct1.raw);
    asn_seq_write_length(parent, seq->len);
    for (u64 i = 0; i < seq->len; i++) {
        asn_seq_write_byte(parent, seq->buffer[i]);
    }
}

bool
asn_seq_init_seq(AsnSeq* seq, Buffer input) {
    u64 index = 0;
    if (index >= input.len) return false;

    AsnOctet1 oct1 = { .raw = input.ptr[index++] };
    if (oct1.tag_type != AsnSequence) return false;

    u64 len = 0;
    if (!asn_read_length(input, &index, &len)) return false;

    if (len > input.len - index) return false;

    input = buf(input.ptr + index, len);
    ft_memcpy(buf(seq->buffer, len), input);
    seq->len = len;

    return true;
}

bool
asn_seq_read_seq(AsnSeq* seq, u64* index, AsnSeq* out) {
    if (*index >= seq->len) return false;

    AsnOctet1 oct1 = { .raw = seq->buffer[(*index)++] };
    if (oct1.tag_type != AsnSequence) return false;

    u64 len = 0;
    if (!asn_read_length(buf(seq->buffer, seq->len), index, &len)) return false;

    if (len > seq->len - *index) return false;

    Buffer sub_seq = buf(&seq->buffer[*index], len);
    ft_memcpy(buf(out->buffer, len), sub_seq);
    out->len = len;

    return true;
}

bool
asn_seq_read_integer(AsnSeq* seq, u64* index, u64* value) {
    if (*index >= seq->len) return false;

    AsnOctet1 oct1 = { .raw = seq->buffer[(*index)++] };
    if (oct1.tag_type != AsnInteger) return false;

    u64 len = 0;
    if (!asn_read_length(buf(seq->buffer, seq->len), index, &len)) return false;

    if (len > seq->len - *index) return false;

    *value = 0;
    while (len--) {
        *value <<= 8;
        *value |= seq->buffer[(*index)++];
    }

    return true;
}

bool
asn_seq_read_object_ident(AsnSeq* seq, u64* index, Buffer* value) {
    if (*index >= seq->len) return false;

    AsnOctet1 oct1 = { .raw = seq->buffer[(*index)++] };
    if (oct1.tag_type != AsnObjectIdentifier) return false;

    u64 len = 0;
    if (!asn_read_length(buf(seq->buffer, seq->len), index, &len)) return false;

    if (len > seq->len - *index) return false;

    value->ptr = &seq->buffer[*index];
    value->len = len;

    *index += len;

    return true;
}

bool
asn_seq_read_null_value(AsnSeq* seq, u64* index, u64* value) {
    if (*index >= seq->len) return false;

    AsnOctet1 oct1 = { .raw = seq->buffer[(*index)++] };
    if (oct1.tag_type != AsnNull) return false;

    if (*index >= seq->len) return false;

    *value = seq->buffer[(*index)++];

    return true;
}

bool
asn_seq_read_octet_str(AsnSeq* seq, u64* index, Buffer* value) {
    if (*index >= seq->len) return false;

    AsnOctet1 oct1 = { .raw = seq->buffer[(*index)++] };
    if (oct1.tag_type != AsnOctetString) return false;

    u64 len = 0;
    if (!asn_read_length(buf(seq->buffer, seq->len), index, &len)) return false;

    if (len > seq->len - *index) return false;

    value->ptr = &seq->buffer[*index];
    value->len = len;

    *index += len;

    return true;
}
