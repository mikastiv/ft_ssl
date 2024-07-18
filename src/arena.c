#include "arena.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static u64
align_up(u64 address, u64 alignment) {
    u64 mask = alignment - 1;
    return (address + mask) & ~mask;
}

bool
arena_init(Arena* arena, u64 size) {
    *arena = (Arena){ 0 };
    arena->block = malloc(size);
    arena->size = size;
    return arena->block != NULL;
}

void*
arena_alloc(Arena* arena, u64 size) {
    arena->index = align_up(arena->index, 16);
    char* address = arena->block + arena->index;
    arena->index += size;

    if (arena->index >= arena->size) {
        arena_free(arena);
        dprintf(STDERR_FILENO, "out of memory\n");
        exit(EXIT_FAILURE);
    }

    if (arena->index > arena->high_watermark) {
        arena->high_watermark = arena->index;
    }

    return address;
}

void
arena_clear(Arena* arena) {
    arena->index = 0;
}

void
arena_free(Arena* arena) {
    free(arena->block);
    *arena = (Arena){ 0 };
}

void
arena_log_watermark(Arena* arena) {
    u64 max = arena->high_watermark;

    if (max >= 1024 * 1024) {
        dprintf(STDERR_FILENO, "arena max memory usage: %.2f MB\n", (float)max / 1024.0f * 1024.0f);
    } else if (max >= 1024) {
        dprintf(STDERR_FILENO, "arena max memory usage: %.2f KB\n", (float)max / 1024.0f);
    } else {
        dprintf(STDERR_FILENO, "arena max memory usage: %" PRIu64 " bytes\n", max);
    }
}
