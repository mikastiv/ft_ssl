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
#define ASN_PKCS5_PBES2 "\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0D"
#define ASN_PKCS5_PBKF2 "\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0C"

typedef struct {
    u8 buffer[ASN_SEQ_MAXSIZE];
    u64 len;
} AsnSeq;

AsnSeq
asn_seq_init(void);

void
asn_seq_add_integer(AsnSeq* seq, u64 value);

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

typedef struct {
    AsnTag tag;
    u64 offset;
    u64 len_size;
    Buffer data;
} AsnEntry;

bool
asn_next_entry(Buffer input, u64 index, AsnEntry* out);

bool
asn_integer_to_u64(Buffer integer, u64* out);

u64
asn_next_entry_offset(AsnEntry entry);

u64
asn_seq_first_entry(AsnEntry entry);
