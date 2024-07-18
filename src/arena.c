#include "arena.h"

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