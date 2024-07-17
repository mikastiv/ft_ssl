#pragma once

#include "ssl.h"

#define MAX_MEMORY (1024 * 1024 * 100)

Command
parse_command(const char* str);

u32
parse_options(Command cmd, void* out_options);

void
usage(const char* command);

void
print_help(Command cmd);
