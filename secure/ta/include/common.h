#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdint.h>

typedef struct buffer {
    uint8_t *data;
    uint32_t len;
} BUFFER;

#endif /* __COMMON_H__ */
