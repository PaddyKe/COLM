/*
 * AES Building blocks.
 * They perform AES ECB encryption
 */

#ifndef AES_CRYPTO_ARM
#define AES_CRYPTO_ARM

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "arm_neon.h"
#define BLOCKSIZE 16
#define AES_NEXT_ROUND_KEY(k, rcon) aes_next_round_key(k, rcon)

extern uint8x16_t zero_vector;

#define AES_ENCRYPT(block, keys) do { \
									block = vrev64q_u8(block); \
                                    for (uint8_t i = 0; i < 9; i++) \
                                    { \
                                        block = vaesmcq_u8(vaeseq_u8(block, keys[i])); \
                                    } \
                                    block = vaeseq_u8(block, keys[9]); \
	                                block = veorq_u8(block, keys[10]); \
                                    block = vrev64q_u8(block); \
								} while (0)

#define AES_DECRYPT(block, keys) do { \
								    block = vrev64q_u8(block); \
                                    block = vaesdq_u8(block, keys[10]); \
                                    for (uint8_t i = 9; i >= 1; i--) \
                                    { \
                                        block = vaesdq_u8(vaesimcq_u8(block), keys[i]); \
                                    } \
                                    block = veorq_u8(block, keys[0]); \
                                    block = vrev64q_u8(block); \
								} while (0)

#define AES_ENCRYPT3(block1, block2, block3, keys) do { \
													block1 = vrev64q_u8(block1); \
													block2 = vrev64q_u8(block2); \
													block3 = vrev64q_u8(block3); \
                                                    for (uint8_t i = 0; i < 9; i++) \
                                                    { \
                                                        block1 = vaesmcq_u8(vaeseq_u8(block1, keys[i])); \
                                                        block2 = vaesmcq_u8(vaeseq_u8(block2, keys[i])); \
                                                        block3 = vaesmcq_u8(vaeseq_u8(block3, keys[i])); \
                                                    } \
                                                    block1 = vaeseq_u8(block1, keys[9]); \
	                                                block1 = veorq_u8(block1, keys[10]); \
                                                    block2 = vaeseq_u8(block2, keys[9]); \
	                                                block2 = veorq_u8(block2, keys[10]); \
                                                    block3 = vaeseq_u8(block3, keys[9]); \
	                                                block3 = veorq_u8(block3, keys[10]); \
                                                    block1 = vrev64q_u8(block1); \
													block2 = vrev64q_u8(block2); \
													block3 = vrev64q_u8(block3); \
												  } while (0)

#define AES_DECRYPT3(block1, block2, block3, keys) do { \
													block1 = vrev64q_u8(block1); \
													block2 = vrev64q_u8(block2); \
													block3 = vrev64q_u8(block3); \
                                                 	block1 = vaesdq_u8(block1, keys[10]); \
													block2 = vaesdq_u8(block2, keys[10]); \
													block3 = vaesdq_u8(block3, keys[10]); \
                                                    for (uint8_t i = 9; i >= 1; i--) \
                                                    { \
                                                        block1 = vaesdq_u8(vaesimcq_u8(block1), keys[i]); \
                                                        block2 = vaesdq_u8(vaesimcq_u8(block2), keys[i]); \
                                                        block3 = vaesdq_u8(vaesimcq_u8(block3), keys[i]); \
                                                    } \
                                                    block1 = veorq_u8(block1, keys[0]); \
                                                    block1 = vrev64q_u8(block1); \
                                                    block2 = veorq_u8(block2, keys[0]); \
                                                    block2 = vrev64q_u8(block2); \
                                                    block3 = veorq_u8(block3, keys[0]); \
													block3 = vrev64q_u8(block3); \
												  } while (0)


#define AES_SET_ENCRYPTION_KEYS(key, encryption_keys) do { \
                                                            encryption_keys[0] = key; \
                                                            encryption_keys[1] = AES_NEXT_ROUND_KEY(key, 0x01); \
                                                            encryption_keys[2] = AES_NEXT_ROUND_KEY(key, 0x02); \
                                                            encryption_keys[3] = AES_NEXT_ROUND_KEY(key, 0x04); \
                                                            encryption_keys[4] = AES_NEXT_ROUND_KEY(key, 0x08); \
                                                            encryption_keys[5] = AES_NEXT_ROUND_KEY(key, 0x10); \
                                                            encryption_keys[6] = AES_NEXT_ROUND_KEY(key, 0x20); \
                                                            encryption_keys[7] = AES_NEXT_ROUND_KEY(key, 0x40); \
                                                            encryption_keys[8] = AES_NEXT_ROUND_KEY(key, 0x80); \
                                                            encryption_keys[9] = AES_NEXT_ROUND_KEY(key, 0x1b); \
                                                            encryption_keys[10] = AES_NEXT_ROUND_KEY(key, 0x36); \
                                                        } while(0)

#define AES_SET_DECRYPTION_KEYS(encryption_keys, decryption_keys) do { \
                                                                decryption_keys[0] = encryption_keys[0]; \
                                                                decryption_keys[1] = vaesimcq_u8(encryption_keys[1]); \
                                                                decryption_keys[2] = vaesimcq_u8(encryption_keys[2]); \
                                                                decryption_keys[3] = vaesimcq_u8(encryption_keys[3]); \
                                                                decryption_keys[4] = vaesimcq_u8(encryption_keys[4]); \
                                                                decryption_keys[5] = vaesimcq_u8(encryption_keys[5]); \
                                                                decryption_keys[6] = vaesimcq_u8(encryption_keys[6]); \
                                                                decryption_keys[7] = vaesimcq_u8(encryption_keys[7]); \
                                                                decryption_keys[8] = vaesimcq_u8(encryption_keys[8]); \
                                                                decryption_keys[9] = vaesimcq_u8(encryption_keys[9]); \
                                                                decryption_keys[10] = encryption_keys[10]; \
                                                            } while (0)

#endif
