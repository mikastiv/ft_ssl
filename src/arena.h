#pragma once

#include "types.h"
#include <stdbool.h>

typedef struct {
    char* block;
    u64 size;
    u64 index;
} Arena;

bool
arena_init(Arena* arena, u64 size);

void*
arena_alloc(Arena* arena, u64 size);

void
arena_clear(Arena* arena);

void
arena_free(Arena* arena);
