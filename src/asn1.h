#pragma once

#include "types.h"

typedef enum {
    AsnBoolean = 0x1,
    AsnInteger = 0x2,
    AsnBitString = 0x3,
    AsnOctetString = 0x4,
    AsnNull = 0x5,
    AsnObjectIdentifier = 0x6,
    AsnUtf8String = 0xC,
    AsnSequence = 0x10,
    AsnSet = 0x11,
    AsnPrintableString = 0x13,
    AsnIA5String = 0x16,
    AsnUtcTime = 0x17,
    AsnGeneralizedTime = 0x18,
} AsnTag;

#define ASN_LONGFORM 31

typedef union {
    struct {
        u8 tag_type  : 5;
        u8 pc        : 1;
        u8 tag_class : 2;
    };

    u8 raw;
} AsnOctet1;

typedef union {
    struct {
        u8 length : 7;
        u8 more   : 1;
    };

    u8 raw;
} AsnLength;

#define ASN_SEQ_MAXSIZE 1024
#define ASN_RSA_ENCRYPTION "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"

typedef struct {
    u8 buffer[ASN_SEQ_MAXSIZE];
    u64 len;
} AsnSeq;

AsnSeq
asn_seq_init(void);

void
asn_seq_add_integer(AsnSeq* seq, u64 value, u64 bitsize);

void
asn_seq_add_null(AsnSeq* seq, u8 value);

void
asn_seq_add_object_ident(AsnSeq* seq, Buffer value);

void
asn_seq_add_octet_str_seq(AsnSeq* seq, AsnSeq* value);

void
asn_seq_add_bit_str_seq(AsnSeq* seq, AsnSeq* value);

void
asn_seq_add_seq(AsnSeq* parent, AsnSeq* seq);

bool
asn_seq_init_seq(AsnSeq* seq, Buffer input);

bool
asn_seq_read_seq(AsnSeq* seq, u64* index, AsnSeq* out);

bool
asn_seq_read_integer(AsnSeq* seq, u64* index, u64* value);

bool
asn_seq_read_object_ident(AsnSeq* seq, u64* index, Buffer* value);

bool
asn_seq_read_null_value(AsnSeq* seq, u64* index, u64* value);

bool
asn_seq_read_octet_str(AsnSeq* seq, u64* index, Buffer* out);
