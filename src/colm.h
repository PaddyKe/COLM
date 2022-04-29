#ifndef COLM_ARM
#define COLM_ARM

#include "aes_crypto.h"
#include <string.h>


uint8x16_t mac(uint8x16_t npub_param, uint8_t* associated_data, const uint64_t data_len, uint8x16_t L, uint8x16_t* aes_round_keys);


int8_t colm0_encrypt(uint8_t* message, uint64_t message_len, uint8_t* associated_data, uint64_t data_len, uint64_t npub, uint8x16_t key, uint64_t* c_len, uint8_t* c);
int8_t colm0_decrypt(uint8_t* ciphertext, uint64_t len, uint8_t* associated_data, uint64_t data_len, uint64_t npub, uint8x16_t key, uint64_t* m_len, uint8_t* message);

int8_t colm127_encrypt(uint8_t* message, uint64_t message_len, uint8_t* associated_data, uint64_t data_len, uint64_t npub, uint8x16_t key, uint64_t* c_len, uint8_t* ciphertext, uint64_t* tag_len, uint8_t* tags);
int8_t colm127_decrypt(uint8_t* ciphertext, uint64_t len, uint8_t* associated_data, uint64_t data_len, uint64_t npub, uint8x16_t key, uint64_t tag_len, uint8_t* tags, uint64_t* m_len, uint8_t* message);

#endif
