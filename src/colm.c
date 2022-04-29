/*
 * This is an implementation of the COLM encryption algorithm instantiated as COLM0 (without intermediate tags) and COLM127 (intermediate tags every 127 blocks)
 * AUTHOR: Patrick Kempf
 * Bachelor thesis at the Philipps university of Marburg
 */


#include "colm.h"


#define EQUALS(a, b) (vaddlvq_u8(veorq_u8(a, b)) == 0)


#define RHO_INPLACE(x, st, w_new) do { \
									w_new = veorq_u8(gf_mul2(st), x); \
									x = veorq_u8(w_new, st); \
									st = w_new; \
								} while(0)

#define RHO_INVERSE_INPLACE(y, st, w_new) do { \
											w_new = gf_mul2(st); \
											st = veorq_u8(st, y); \
											y = veorq_u8(w_new, st); \
										} while(0)

#define LOAD_BLOCK(ptr) vrev64q_u8(vld1q_u8(ptr)) // load and change endianness
#define STORE_BLOCK(ptr, block) vst1q_u8(ptr, vrev64q_u8(block))

uint8x16_t gf_mul2(uint8x16_t x)
{
	uint8x16_t temp = vreinterpretq_u8_s8(vshrq_n_s8(vreinterpretq_s8_u8(x), 7));
	uint8x16_t x64 = vshlq_n_u8(x, 1); // multiply by two
	x64 = vorrq_u8(x64, vandq_u8(vextq_u8(temp, zero_vector, 1), ((uint8x16_t){1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0}))); // handle overflow bit from lower bytes to higher bytes
	return veorq_u8(x64, vandq_u8(vdupq_laneq_u8(temp, 0), (uint8x16_t){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87}));
}

uint8x16_t gf_mul3(uint8x16_t x)
{
	return veorq_u8(gf_mul2(x), x);
}

uint8x16_t gf_mul7(uint8x16_t x)
{
	uint8x16_t tmp = gf_mul2(x);
	return veorq_u8(veorq_u8(gf_mul2(tmp), tmp), x);
}

uint8x16_t mac(uint8x16_t npub_param, uint8_t* associated_data, const uint64_t data_len, uint8x16_t L, uint8x16_t* aes_round_keys)
{
	uint8_t* in = associated_data;
	uint64_t len = data_len;
	uint8_t buf[16] = { 0 };
	uint8x16_t block, v, delta = gf_mul3(L);
	v = veorq_u8(vrev64q_u8(npub_param), delta);
	AES_ENCRYPT(v, aes_round_keys);

	while (len >= BLOCKSIZE) {
		block = LOAD_BLOCK(in);//vld1q_u8(in);

		delta = gf_mul2(delta);

		block = veorq_u8(block, delta);

		AES_ENCRYPT(block, aes_round_keys);
		
		v = veorq_u8(v, block);

		in += BLOCKSIZE;
		len -= BLOCKSIZE;
	}

	if (len > 0) { /* last block partial */
		delta = gf_mul7(delta);
		memcpy(buf, in, len);
		buf[len] ^= 0x80; /* padding */
		block = LOAD_BLOCK(buf);
		block = veorq_u8(delta, block);

		AES_ENCRYPT(block, aes_round_keys);
		v = veorq_u8(v, block);
	}

	return v;
}



/* ----------------------- COLM 0 ------------------------- */

int8_t colm0_encrypt(uint8_t* message, uint64_t message_len, uint8_t* associated_data, uint64_t data_len, uint64_t npub, uint8x16_t key, uint64_t* c_len, uint8_t* ciphertext)
{
	uint8x16_t checksum = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8x16_t w, w_tmp;
	uint8x16_t block;
	uint8x16_t aes_round_keys[11];
	uint8x16_t delta_m, delta_c;
	uint8x16_t L = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	const uint8_t* in = message;
	uint8_t* out = ciphertext;
	uint64_t remaining = message_len;
	uint8_t buf[BLOCKSIZE] = { 0 };
	
	*c_len = message_len + BLOCKSIZE;
	
	AES_SET_ENCRYPTION_KEYS(key, aes_round_keys);
	
	AES_ENCRYPT(L, aes_round_keys);

	w = mac(vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(npub), ((uint64x1_t){0x0000800000000000}))), associated_data, data_len, L, aes_round_keys);
	

	delta_m = L;
	delta_c = gf_mul3(gf_mul3(L));



	while(remaining > BLOCKSIZE)
	{
		delta_m = gf_mul2(delta_m);

		block = LOAD_BLOCK(in);
		
		checksum = veorq_u8(checksum, block);
		
		block = veorq_u8(block, delta_m);

		AES_ENCRYPT(block, aes_round_keys);

		delta_c = gf_mul2(delta_c);

		RHO_INPLACE(block, w, w_tmp);

		AES_ENCRYPT(block, aes_round_keys);

		block = veorq_u8(block, delta_c);

		STORE_BLOCK(out, block);

		in += BLOCKSIZE;
		out += BLOCKSIZE;
		remaining -= BLOCKSIZE;
	}


	// handyle remaining bytes
	memcpy(buf, in, remaining);
	
	delta_m = gf_mul7(delta_m);
	delta_c = gf_mul7(delta_c);

	// pad if nessesary
	if (remaining < BLOCKSIZE) {
		buf[remaining] = 0x80;
		delta_m = gf_mul7(delta_m);
		delta_c = gf_mul7(delta_c);
	}

	block = LOAD_BLOCK(buf);//vld1q_u8(buf);

	block = checksum = veorq_u8(checksum, block);
	
	block = veorq_u8(block, delta_m);

	AES_ENCRYPT(block, aes_round_keys);

	RHO_INPLACE(block, w, w_tmp);

	AES_ENCRYPT(block, aes_round_keys);

	block = veorq_u8(block, delta_c);

	STORE_BLOCK(out, block);

	out += BLOCKSIZE;
	

	// if remaining == 0
	if (remaining == 0) return 0;



	// add checksum
	delta_m = gf_mul2(delta_m);
	delta_c = gf_mul2(delta_c);

	block = veorq_u8(delta_m, checksum);
	AES_ENCRYPT(block, aes_round_keys);

	RHO_INPLACE(block, w, w_tmp);

	AES_ENCRYPT(block, aes_round_keys);
	block = veorq_u8(block, delta_c);

	STORE_BLOCK((uint8_t*)buf, block);
	memcpy(out, buf, remaining);

	return 0;
}

int8_t colm0_decrypt(uint8_t* ciphertext, uint64_t len, uint8_t* associated_data, uint64_t data_len, uint64_t npub, uint8x16_t key, uint64_t* m_len, uint8_t* message)
{
	uint8x16_t checksum = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8x16_t w, w_tmp;
	uint8x16_t block;
	uint8x16_t encryption_keys[11];
	uint8x16_t decryption_keys[11];
	uint8x16_t delta_m, delta_c;
	uint8x16_t L = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	const uint8_t* in = ciphertext;
	uint8_t* out = message;
	uint64_t remaining = *m_len = len - BLOCKSIZE;
	uint32_t i;
	uint8_t buf[BLOCKSIZE] = { 0 }; 
	
	if (len < BLOCKSIZE)
	{
		// -1 => invalid size of ciphertext
		return -1;
	}

	AES_SET_ENCRYPTION_KEYS(key, encryption_keys);
	AES_SET_DECRYPTION_KEYS(encryption_keys, decryption_keys);
	
	AES_ENCRYPT(L, encryption_keys);
	delta_m = L;
	delta_c = gf_mul3(gf_mul3(L));

	w = mac(vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(npub), ((uint64x1_t){0x0000800000000000}))), associated_data, data_len, L, encryption_keys);


	while (remaining > BLOCKSIZE) {
		delta_c = gf_mul2(delta_c);

		block = LOAD_BLOCK(in);

		block = veorq_u8(block, delta_c);

		AES_DECRYPT(block, decryption_keys);
		
		delta_m = gf_mul2(delta_m);

		RHO_INVERSE_INPLACE(block, w, w_tmp);

		AES_DECRYPT(block, decryption_keys);
		
		block = veorq_u8(block, delta_m);
		
		checksum = veorq_u8(checksum, block);
		
		STORE_BLOCK(out, block);

		in += BLOCKSIZE;
		out += BLOCKSIZE;
		remaining -= BLOCKSIZE;
	}



	delta_m = gf_mul7(delta_m);
	delta_c = gf_mul7(delta_c);


	if (remaining < BLOCKSIZE) {
		delta_m = gf_mul7(delta_m);
		delta_c = gf_mul7(delta_c);
	}

	block = LOAD_BLOCK(in);
	block = veorq_u8(block, delta_c);
	AES_DECRYPT(block, decryption_keys);

	/* (X,W') = rho^-1(block, W) */
	RHO_INVERSE_INPLACE(block, w, w_tmp);

	AES_DECRYPT(block, decryption_keys);
	block = veorq_u8(block, delta_m);
	/* block now contains M[l] = M[l+1] */
	
	checksum = veorq_u8(checksum, block);
	/* checksum now contains M*[l] */
	in += BLOCKSIZE;
	
	/* output last (maybe partial) plaintext block */
	
	// I had to store the block instead of the checksum.
	STORE_BLOCK(buf, checksum);
	//STORE_BLOCK(buf, block);
	memcpy(out, buf, remaining);

	/* work on M[l+1] */
	delta_m = gf_mul2(delta_m);
	delta_c = gf_mul2(delta_c);

	block = veorq_u8(delta_m, block);
	AES_ENCRYPT(block, encryption_keys);
	
	/* (Y,W') = rho(block, W) */
	RHO_INPLACE(block, w, w_tmp);

	AES_ENCRYPT(block, encryption_keys);
	block = veorq_u8(block, delta_c);
	/* block now contains C'[l+1] */

	STORE_BLOCK(buf, block);
	if (memcmp(in, buf, remaining) != 0) {
		return -2;
	}

	if (remaining < BLOCKSIZE) {
		STORE_BLOCK(buf, checksum);
		if (buf[remaining] != 0x80) {
			return -3;
		}
		for (i = remaining+1; i < BLOCKSIZE; i++) {
			if (buf[i] != 0) {
				return -4;
			}
		}
	}

	return 0;	
}





/* ------------------ COLM 127 ------------------- */

int8_t colm127_encrypt(uint8_t* message, uint64_t message_len, uint8_t* associated_data, uint64_t data_len, uint64_t npub, uint8x16_t key, uint64_t* c_len, uint8_t* ciphertext, uint64_t* tag_len, uint8_t* tags)
{

	uint8x16_t checksum = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8x16_t w, w_tmp;
	uint8x16_t block;
	uint8x16_t aes_round_keys[11];
	uint8x16_t delta_m, delta_c;
	uint8x16_t L = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	const uint8_t* in = message;
	uint8_t* out = ciphertext;
	uint8_t* tag_out = tags;
	uint64_t remaining = message_len;
	uint8_t buf[BLOCKSIZE] = { 0 };
	uint64_t iteration_counter = 1;

	*c_len = message_len + BLOCKSIZE;

	AES_SET_ENCRYPTION_KEYS(key, aes_round_keys);

	AES_ENCRYPT(L, aes_round_keys);
	delta_m = L; 
	delta_c = gf_mul3(gf_mul3(L));

	w = mac(vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(npub), ((uint64x1_t){0x007F800000000000}))), associated_data, data_len, L, aes_round_keys);
	
	while(remaining > BLOCKSIZE)
	{
		delta_m = gf_mul2(delta_m);
		delta_c = gf_mul2(delta_c);

		block = LOAD_BLOCK(in);
		
		checksum = veorq_u8(checksum, block);

		block = veorq_u8(block, delta_m);

		AES_ENCRYPT(block, aes_round_keys);

		RHO_INPLACE(block, w, w_tmp);

		// calculate Tag
		if (iteration_counter % 127 == 0)
		{
			delta_c = gf_mul2(delta_c);
			uint8x16_t tag = w;
			AES_ENCRYPT(tag, aes_round_keys);
			tag = veorq_u8(tag, delta_c);
			STORE_BLOCK(tag_out, tag);
			tag_out += BLOCKSIZE;
			*tag_len += BLOCKSIZE;
		}

		AES_ENCRYPT(block, aes_round_keys);
		
		block = veorq_u8(block, delta_c);

		STORE_BLOCK(out, block);

		in += BLOCKSIZE;
		out += BLOCKSIZE;
		remaining -= BLOCKSIZE;
		iteration_counter++;
	}


	// handyle remaining bytes
	memcpy(buf, in, remaining);
	
	delta_m = gf_mul7(delta_m);
	delta_c = gf_mul7(delta_c);

	// pad if nessesary
	if (remaining < BLOCKSIZE) {
		buf[remaining] = 0x80;
		delta_m = gf_mul7(delta_m);
		delta_c = gf_mul7(delta_c);
	}

	block = LOAD_BLOCK(buf);//vld1q_u8(buf);

	block = checksum = veorq_u8(checksum, block);
	
	block = veorq_u8(block, delta_m);

	AES_ENCRYPT(block, aes_round_keys);

	RHO_INPLACE(block, w, w_tmp);

	AES_ENCRYPT(block, aes_round_keys);

	block = veorq_u8(block, delta_c);

	STORE_BLOCK(out, block);

	out += BLOCKSIZE;
	
	// calculate Tag
	if (iteration_counter % 127 == 0)
	{
		delta_c = gf_mul2(delta_c);
		uint8x16_t tag = w;
		AES_ENCRYPT(w, aes_round_keys);
		tag = veorq_u8(tag, delta_c);
		STORE_BLOCK(tag_out, tag);
		tag_out += BLOCKSIZE;
		*tag_len += BLOCKSIZE;
	}

	// if remaining == 0
	if (remaining == 0) return 0;



	// add checksum
	delta_m = gf_mul2(delta_m);
	delta_c = gf_mul2(delta_c);

	block = veorq_u8(delta_m, checksum);
	AES_ENCRYPT(block, aes_round_keys);

	RHO_INPLACE(block, w, w_tmp);

	AES_ENCRYPT(block, aes_round_keys);
	block = veorq_u8(block, delta_c);

	STORE_BLOCK((uint8_t*)buf, block);
	memcpy(out, buf, remaining);

	return 0;
}

int8_t colm127_decrypt(uint8_t* ciphertext, uint64_t len, uint8_t* associated_data, uint64_t data_len, uint64_t npub, uint8x16_t key, uint64_t tag_len, uint8_t* tags, uint64_t* m_len, uint8_t* message)
{

	uint8x16_t checksum = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8x16_t w, w_tmp;
	uint8x16_t block;
	uint8x16_t encryption_keys[11];
	uint8x16_t decryption_keys[11];
	uint8x16_t delta_m, delta_c;
	uint8x16_t L = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	const uint8_t* in = ciphertext;
	uint8_t* out = message;
	uint8_t* tag_in = tags;
	uint64_t remaining = *m_len = len - BLOCKSIZE;
	uint32_t i;
	uint8_t buf[BLOCKSIZE] = { 0 };
	uint64_t iteration_counter = 1;
	uint8_t itag;

	// TODO add a check for tag length

	if (len < BLOCKSIZE)
	{
		// -1 => invalid size of ciphertext
		return -1;
	}

	AES_SET_ENCRYPTION_KEYS(key, encryption_keys);
	AES_SET_DECRYPTION_KEYS(encryption_keys, decryption_keys);

	AES_ENCRYPT(L, encryption_keys);
	delta_m = L;
	delta_c = gf_mul3(gf_mul3(L));

	w = mac(vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(npub), ((uint64x1_t){0x007F800000000000}))), associated_data, data_len, L, encryption_keys);
	
	while (remaining > BLOCKSIZE) {
		itag = iteration_counter % 127;
		delta_c = gf_mul2(delta_c);
		delta_m = gf_mul2(delta_m);

		block = LOAD_BLOCK(in);

		if (itag == 0)
		{
			delta_c = gf_mul2(delta_c);
		}

		block = veorq_u8(block, delta_c);

		AES_DECRYPT(block, decryption_keys);
		
		RHO_INVERSE_INPLACE(block, w, w_tmp);

		// verify tag
		if (itag == 0)
		{	
			
			uint8x16_t tag = LOAD_BLOCK(tag_in);
			tag = veorq_u8(tag, delta_c);
			AES_DECRYPT(tag, decryption_keys);
			if (!EQUALS(tag, w))
			{
				return -5;
			}
			tag_in += BLOCKSIZE;
		}

		AES_DECRYPT(block, decryption_keys);
		
		block = veorq_u8(block, delta_m);
		
		checksum = veorq_u8(checksum, block);
		
		STORE_BLOCK(out, block);

		in += BLOCKSIZE;
		out += BLOCKSIZE;
		remaining -= BLOCKSIZE;
		iteration_counter++;
	}

	delta_m = gf_mul7(delta_m);
	delta_c = gf_mul7(delta_c);


	if (remaining < BLOCKSIZE) {
		delta_m = gf_mul7(delta_m);
		delta_c = gf_mul7(delta_c);
	}

	block = LOAD_BLOCK(in);
	block = veorq_u8(block, delta_c);
	AES_DECRYPT(block, decryption_keys);

	/* (X,W') = rho^-1(block, W) */
	RHO_INVERSE_INPLACE(block, w, w_tmp);

	AES_DECRYPT(block, decryption_keys);
	block = veorq_u8(block, delta_m);
	/* block now contains M[l] = M[l+1] */
	
	checksum = veorq_u8(checksum, block);
	/* checksum now contains M*[l] */
	in += BLOCKSIZE;
	
	/* output last (maybe partial) plaintext block */
	

	// I had to store the block instead of the checksum.
	STORE_BLOCK(buf, checksum);
	//STORE_BLOCK(buf, block);
	memcpy(out, buf, remaining);

	if (iteration_counter % 127 == 0)
	{		
		delta_c = gf_mul2(delta_c);
		uint8x16_t tag = LOAD_BLOCK(tag_in);
		tag = veorq_u8(tag, delta_c);
		AES_DECRYPT(tag, decryption_keys);
		if (!EQUALS(tag, w))
		{
			return -5;
		}
		tag_in += BLOCKSIZE;
	}

	/* work on M[l+1] */
	delta_m = gf_mul2(delta_m);
	delta_c = gf_mul2(delta_c);

	block = veorq_u8(delta_m, block);
	AES_ENCRYPT(block, encryption_keys);
	
	/* (Y,W') = rho(block, W) */
	RHO_INPLACE(block, w, w_tmp);

	AES_ENCRYPT(block, encryption_keys);
	block = veorq_u8(block, delta_c);
	/* block now contains C'[l+1] */

	STORE_BLOCK(buf, block);
	if (memcmp(in, buf, remaining) != 0) {
		return -2;
	}

	if (remaining < BLOCKSIZE) {
		STORE_BLOCK(buf, checksum);
		if (buf[remaining] != 0x80) {
			return -3;
		}
		for (i = remaining+1; i < BLOCKSIZE; i++) {
			if (buf[i] != 0) {
				return -4;
			}
		}
	}

	return 0;
}
