#pragma once

#include "ssl.h"

Command
parse_command(const char* str);

u32
parse_options(Command cmd, void* out_options);

void
usage(void);

void
print_help(void);
