#include "utils.h"

u64
ft_strlen(const char* str) {
    u64 len = 0;
    while (str[len]) len++;
    return len;
}
