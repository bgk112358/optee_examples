#ifndef __SECURE_API_H__
#define __SECURE_API_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define RSA2048_KEY1 1u
#define RSA2048_KEY2 2u
#define RSA2048_KEY3 3u
#define RSA2048_KEY4 4u

int32_t rsa_keygen(uint32_t key_slot, int32_t key_size);

#endif __SECURE_API_H__

