/*
 * This implementation is an optimized implementaiton of the COLM ecncryption algorithm instantiated as COLM0 (without intermediate tags) and COLM127 (with intermediate tags every 127 blocks)
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


#define SET_ENCRPTION_KEYS(key, round_keys) AES_SET_ENCRYPTION_KEYS(key, round_keys);
#define SET_DECRPTION_KEYS(encryption_round_keys, decryption_round_keys) AES_SET_DECRYPTION_KEYS(encryption_round_keys, decryption_round_keys)


// perform galois multiplication with 2
uint8x16_t gf_mul2(uint8x16_t x)
{
	uint8x16_t temp = vreinterpretq_u8_s8(vshrq_n_s8(vreinterpretq_s8_u8(x), 7));
	uint8x16_t x64 = vshlq_n_u8(x, 1); // multiply by two
	x64 = vorrq_u8(x64, vandq_u8(vextq_u8(temp, zero_vector, 1), ((uint8x16_t){1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0}))); // handle overflow bit from lower bytes to higher bytes
	return veorq_u8(x64, vandq_u8(vdupq_laneq_u8(temp, 0), (uint8x16_t){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87}));
}

// perform galois multiplication with 3 (x * 2 + x)
uint8x16_t gf_mul3(uint8x16_t x)
{
	return veorq_u8(gf_mul2(x), x);
}

// perform galois multiplication with 7 (((2 * x) * 2) + (2 * x) + x)
uint8x16_t gf_mul7(uint8x16_t x)
{
	uint8x16_t tmp = gf_mul2(x);
	return veorq_u8(veorq_u8(gf_mul2(tmp), tmp), x);
}


// the first part of the colm cipher: calculate the "mac of the authenticated data"
uint8x16_t mac(uint8x16_t npub_param, uint8_t* associated_data, const uint64_t data_len, uint8x16_t L, uint8x16_t* aes_round_keys)
{
	uint8_t* in = associated_data;
	uint64_t len = data_len;
	uint8_t buf[BLOCKSIZE] = { 0 };
	uint8x16_t block, v, delta;
	uint8x16_t block1, block2, block3;
	uint8x16_t delta1, delta2, delta3;
	uint8x16_t tmp;
	
	delta = delta3= gf_mul3(L);

	v = veorq_u8(vrev64q_u8(npub_param), delta);
	AES_ENCRYPT(v, aes_round_keys);
	
    // this loop performs parallel processing of the authenticated data
	while (len >= 3 * BLOCKSIZE)
	{
		delta1 = gf_mul2(delta3);
		delta2 = gf_mul2(delta1);
		delta3 = gf_mul2(delta2);

		block1 = LOAD_BLOCK(in);
		block2 = LOAD_BLOCK(in + BLOCKSIZE);
		block3 = LOAD_BLOCK(in + (2 * BLOCKSIZE));

		block1 = veorq_u8(block1, delta1);
		block2 = veorq_u8(block2, delta2);
		block3 = veorq_u8(block3, delta3);

		AES_ENCRYPT3(block1, block2, block3, aes_round_keys);

		v = veorq_u8(v, block1);
		v = veorq_u8(v, block2);
		v = veorq_u8(v, block3);

		in += 3 * BLOCKSIZE;
		len -= 3 * BLOCKSIZE;
	}

	delta = delta3;

    // take care of the remaining blocks of the authenticated data(if the authenticated data is not a multiple of 3 * BLOCKSIZE)
	while (len >= BLOCKSIZE)
	{
		delta = gf_mul2(delta);
		block = LOAD_BLOCK(in);
		block = tmp = veorq_u8(block, delta);
		AES_ENCRYPT(tmp, aes_round_keys);
		v = veorq_u8(tmp, block);
		in += BLOCKSIZE;
		len -= BLOCKSIZE;
	}


    // last block
    // here we finish up the mac
	if (len > 0) { /* last block partial */
		delta = gf_mul7(delta);
		memcpy(buf, in, len);
		buf[len] ^= 0x80; /* padding */
		block = LOAD_BLOCK(buf);
		block = tmp = veorq_u8(delta, block);
		AES_ENCRYPT(tmp, aes_round_keys);
		v = veorq_u8(tmp, block);
	}

	return v;
}



/* ----------------------- COLM 0 ------------------------- */

int8_t colm0_encrypt(uint8_t* message, uint64_t message_len, uint8_t* associated_data, uint64_t data_len, uint64_t npub, uint8x16_t key, uint64_t* c_len, uint8_t* ciphertext)
{

    // prepare initial variables
	uint8x16_t checksum = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8x16_t w, w_tmp;
	uint8x16_t block1, block2, block3, block;
	uint8x16_t aes_round_keys[11];
	uint8x16_t delta_m1, delta_m2, delta_m3, delta_m;
	uint8x16_t delta_c1, delta_c2, delta_c3, delta_c;
	uint8x16_t L = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	
    // the pointers are used to move dynamically through the in and output
	const uint8_t* in = message;
	uint8_t* out = ciphertext;
	uint64_t remaining = message_len;
	uint8_t buf[BLOCKSIZE] = { 0 };
	
	*c_len = message_len + BLOCKSIZE;
	
    // as we use AES ECB as building block of colm we can prepare the roundkeys.
	SET_ENCRPTION_KEYS(key, aes_round_keys);
	
	
	AES_ENCRYPT(L, aes_round_keys);

    // calculate MAC of authenticatedcata
	w = mac(vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(npub), ((uint64x1_t){0x0000800000000000}))), associated_data, data_len, L, aes_round_keys);
	
    // prepare more variables
	delta_m3 = L;
	delta_c3 = gf_mul3(gf_mul3(L));


    // this loop makes use of pipelining to parralelize the encryption process
    // this upps the performance of the encryption up to (almost) three times
	while(remaining > 3 * BLOCKSIZE)
	{
		delta_m1 = gf_mul2(delta_m3);
		delta_m2 = gf_mul2(delta_m1);
		delta_m3 = gf_mul2(delta_m2);

		block1 = LOAD_BLOCK(in);
		block2 = LOAD_BLOCK(in + BLOCKSIZE);
		block3 = LOAD_BLOCK(in + (2 * BLOCKSIZE));
		
		checksum = veorq_u8(checksum, block1);
		checksum = veorq_u8(checksum, block2);
		checksum = veorq_u8(checksum, block3);

		block1 = veorq_u8(block1, delta_m1);
		block2 = veorq_u8(block2, delta_m2);
		block3 = veorq_u8(block3, delta_m3);

		AES_ENCRYPT3(block1, block2, block3, aes_round_keys);

		delta_c1 = gf_mul2(delta_c3);
		delta_c2 = gf_mul2(delta_c1);
		delta_c3 = gf_mul2(delta_c2);
		
		RHO_INPLACE(block1, w, w_tmp);
		RHO_INPLACE(block2, w, w_tmp);
		RHO_INPLACE(block3, w, w_tmp);

		AES_ENCRYPT3(block1, block2, block3, aes_round_keys);
		
		block1 = veorq_u8(block1, delta_c1);
		block2 = veorq_u8(block2, delta_c2);
		block3 = veorq_u8(block3, delta_c3);

		STORE_BLOCK(out, block1);
		STORE_BLOCK(out + BLOCKSIZE, block2);
		STORE_BLOCK(out + (2 * BLOCKSIZE), block3);

		in += 3 * BLOCKSIZE;
		out += 3 * BLOCKSIZE;
		remaining -= 3 * BLOCKSIZE;
	}

	delta_m = delta_m3;
	delta_c = delta_c3;

    // finish up the remaining block (at max 2)
	while (remaining > BLOCKSIZE)
	{
		delta_m = gf_mul2(delta_m);
		delta_c = gf_mul2(delta_c);

		block = LOAD_BLOCK(in);
		checksum = veorq_u8(checksum, block);
		
		block = veorq_u8(block, delta_m);

		AES_ENCRYPT(block, aes_round_keys);

		RHO_INPLACE(block, w, w_tmp);

		AES_ENCRYPT(block, aes_round_keys);

		block = veorq_u8(block, delta_c);

		STORE_BLOCK(out, block);

		in += BLOCKSIZE;
		out += BLOCKSIZE;
		remaining -= BLOCKSIZE;
	}




	// handdle remaining bytes
	memcpy(buf, in, remaining);
	
	delta_m = gf_mul7(delta_m);
	delta_c = gf_mul7(delta_c);

	// pad if nessesary
	if (remaining < BLOCKSIZE) {
		buf[remaining] = 0x80;
		delta_m = gf_mul7(delta_m);
		delta_c = gf_mul7(delta_c);
	}

	block = LOAD_BLOCK(buf);

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

	// add tag
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


/*
 * COLM 0 is an mode of operation of AES. It is an authenticated encryption scheme (like AES-GCM) with the advantage of nonce misuse resistance.
 * COLM 0 will output an tag at the end of an encryption (like AES-GCM)
 */
int8_t colm0_decrypt(uint8_t* ciphertext, uint64_t len, uint8_t* associated_data, uint64_t data_len, uint64_t npub, uint8x16_t key, uint64_t* m_len, uint8_t* message)
{
    // prepare initial variables
	uint8x16_t checksum = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8x16_t w, w_tmp;
	uint8x16_t block1, block2, block3, block;
	uint8x16_t aes_encryption_keys[11];
	uint8x16_t aes_decryption_keys[11];
	uint8x16_t delta_m1, delta_m2, delta_m3, delta_m;
	uint8x16_t delta_c1, delta_c2, delta_c3, delta_c;
	uint8x16_t L = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    // the pointers are used to move dynamically through the in and output
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

    // we are decryption but we still need the encryption keys to calculate the MAC and to derive the decryption keys from them
	SET_ENCRPTION_KEYS(key, aes_encryption_keys);
	SET_DECRPTION_KEYS(aes_encryption_keys, aes_decryption_keys);
	
    // prepare more variables
	AES_ENCRYPT(L, aes_encryption_keys);
	delta_m3 = L;
	delta_c3 = gf_mul3(gf_mul3(L));

    // calculate the MAX of the authenticated data
	w = mac(vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(npub), ((uint64x1_t){0x0000800000000000}))), associated_data, data_len, L, aes_encryption_keys);

    // this loop makes use of pipelining to parralelize the decryption process
    // this upps the performance of the decryption up to (almost) three times
	while (remaining > 3 * BLOCKSIZE) {
		delta_c1 = gf_mul2(delta_c3);
		delta_c2 = gf_mul2(delta_c1);
		delta_c3 = gf_mul2(delta_c2);

		block1 = LOAD_BLOCK(in);
		block2 = LOAD_BLOCK(in + BLOCKSIZE);
		block3 = LOAD_BLOCK(in + (2 * BLOCKSIZE));

		block1 = veorq_u8(block1, delta_c1);
		block2 = veorq_u8(block2, delta_c2);
		block3 = veorq_u8(block3, delta_c3);

		AES_DECRYPT3(block1, block2, block3, aes_decryption_keys);

		delta_m1 = gf_mul2(delta_m3);
		delta_m2 = gf_mul2(delta_m1);
		delta_m3 = gf_mul2(delta_m2);

		RHO_INVERSE_INPLACE(block1, w, w_tmp);
		RHO_INVERSE_INPLACE(block2, w, w_tmp);
		RHO_INVERSE_INPLACE(block3, w, w_tmp);


		AES_DECRYPT3(block1, block2, block3, aes_decryption_keys);

		block1 = veorq_u8(block1, delta_m1);
		block2 = veorq_u8(block2, delta_m2);
		block3 = veorq_u8(block3, delta_m3);
		
		checksum = veorq_u8(checksum, block1);
		checksum = veorq_u8(checksum, block2);
		checksum = veorq_u8(checksum, block3);
		
		STORE_BLOCK(out, block1);
		STORE_BLOCK(out + BLOCKSIZE, block2);
		STORE_BLOCK(out + (2 * BLOCKSIZE), block3);

		in += 3 * BLOCKSIZE;
		out += 3 * BLOCKSIZE;
		remaining -= 3 * BLOCKSIZE;
	}

	delta_m = delta_m3;
	delta_c = delta_c3;

    // decrypt the remaining blocks
	while (remaining > BLOCKSIZE) {
		delta_m = gf_mul2(delta_m);
		delta_c = gf_mul2(delta_c);

		block = LOAD_BLOCK(in);
		block = veorq_u8(block, delta_c);

		AES_DECRYPT(block, aes_decryption_keys);

		/* (X,W') = rho^-1(block, W) */
		RHO_INVERSE_INPLACE(block, w, w_tmp);

		AES_DECRYPT(block, aes_decryption_keys);
		block = veorq_u8(block, delta_m);
		
		checksum = veorq_u8(checksum, block);

		STORE_BLOCK(out, block);

		in += BLOCKSIZE;
		out += BLOCKSIZE;
		remaining -= BLOCKSIZE;
	}

	// finish up the decryption

	delta_m = gf_mul7(delta_m);
	delta_c = gf_mul7(delta_c);


	if (remaining < BLOCKSIZE) {
		delta_m = gf_mul7(delta_m);
		delta_c = gf_mul7(delta_c);
	}

	block = LOAD_BLOCK(in);
	block = veorq_u8(block, delta_c);
	AES_DECRYPT(block, aes_decryption_keys);

	/* (X,W') = rho^-1(block, W) */
	RHO_INVERSE_INPLACE(block, w, w_tmp);

	AES_DECRYPT(block, aes_decryption_keys);
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
	AES_ENCRYPT(block, aes_encryption_keys);
	
	/* (Y,W') = rho(block, W) */
	RHO_INPLACE(block, w, w_tmp);

	AES_ENCRYPT(block, aes_encryption_keys);
	block = veorq_u8(block, delta_c);
	/* block now contains C'[l+1] */

	STORE_BLOCK(buf, block);

    // this is an important part. We need to verify the TAG
	if (memcmp(in, buf, remaining) != 0) {
		return -2;
	}

	if (remaining < BLOCKSIZE) {
		STORE_BLOCK(buf, checksum);
        // check padding
		if (buf[remaining] != 0x80) {
			return -3;
		}
		// the remaining data has to be zero (padding scheme)
		for (i = remaining+1; i < BLOCKSIZE; i++) {
			if (buf[i] != 0) {
				return -4;
			}
		}
	}

	return 0;	
}





/* ------------------ COLM 127 ------------------- */

/*
 * COLM 127 is the same encryption algorithm as COLM 127 only a little bit instanciated.
 * COLM 127 will work exactly the same as COLM 0 with the difference that it will generate intermediate tags every 127. block.
 * In this implementation the intermediate tags will be outputted in a seperate array.
 * In a production implementation this should be changed so that the intermediate tags will be outputted after each 127 cipher text blocks within the same output array.
 */

int8_t colm127_encrypt(uint8_t* message, uint64_t message_len, uint8_t* associated_data, uint64_t data_len, uint64_t npub, uint8x16_t key, uint64_t* c_len, uint8_t* ciphertext, uint64_t* tag_len, uint8_t* tags)
{
    // initialize variables
	uint8x16_t checksum = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8x16_t w, w_tmp;
	uint8x16_t block1, block2, block3, block;
	uint8x16_t aes_round_keys[11];
	uint8x16_t delta_m1, delta_m2, delta_m3, delta_m;
	uint8x16_t delta_c1, delta_c2, delta_c3, delta_c;
	uint8x16_t L = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8x16_t w_tag;

    // a few pointers to dynamically move arrount in the in/ouput arrays
	const uint8_t* in = message;
	uint8_t* out = ciphertext;
	uint8_t* tag_out = tags;
	uint64_t remaining = message_len;
	uint8_t buf[BLOCKSIZE] = { 0 };
	uint64_t iteration_counter = 3;
	uint8_t itag = 0;

	*c_len = message_len + BLOCKSIZE;
	SET_ENCRPTION_KEYS(key, aes_round_keys);
	

	AES_ENCRYPT(L, aes_round_keys);
	delta_m3 = L;
	delta_c3 = gf_mul3(gf_mul3(L));
	
    // calculate MAC of authenticated data
	w = mac(vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(npub), ((uint64x1_t){0x007F800000000000}))), associated_data, data_len, L, aes_round_keys);
	

    // parallel encryption of main blocks
	while(remaining > 3 * BLOCKSIZE)
	{
		itag = iteration_counter % 127;

		delta_c1 = gf_mul2(delta_c3);
		delta_c2 = gf_mul2(delta_c1);
		delta_c3 = gf_mul2(delta_c2);
	
		delta_m1 = gf_mul2(delta_m3);
		delta_m2 = gf_mul2(delta_m1);
		delta_m3 = gf_mul2(delta_m2);
		
		block1 = LOAD_BLOCK(in);
		block2 = LOAD_BLOCK(in + BLOCKSIZE);
		block3 = LOAD_BLOCK(in + (2 * BLOCKSIZE));
		
		checksum = veorq_u8(checksum, block1);
		checksum = veorq_u8(checksum, block2);
		checksum = veorq_u8(checksum, block3);;

		block1 = veorq_u8(block1, delta_m1);
		block2 = veorq_u8(block2, delta_m2);
		block3 = veorq_u8(block3, delta_m3);

		AES_ENCRYPT3(block1, block2, block3, aes_round_keys);

		RHO_INPLACE(block1, w, w_tmp); if (itag == 2) w_tag = w;
		RHO_INPLACE(block2, w, w_tmp); if (itag == 1) w_tag = w;
		RHO_INPLACE(block3, w, w_tmp); if (itag == 0) w_tag = w;

		// calculate intermediate tag depending on the remaining blocks till the tag
		switch (itag)
		{
			case 2: // tag "after" block1
				delta_c1 = delta_c2;
				delta_c = delta_c2;
				delta_c2 = delta_c3;
				delta_c3 = gf_mul2(delta_c3);
				break;
			case 1: // tag "after" block2
				delta_c2 = delta_c3;
				delta_c = delta_c3;
				delta_c3 = gf_mul2(delta_c3);
				break;
			case 0: // tag "after" block3
				delta_c3 = gf_mul2(delta_c3);
				delta_c = delta_c3;
				break;
			default:
				break;
		}

		if (itag <= 2)
		{	
			uint8x16_t tag = w_tag;
			AES_ENCRYPT(tag, aes_round_keys);
			tag = veorq_u8(tag, delta_c);
			STORE_BLOCK(tag_out, tag);
			tag_out += BLOCKSIZE;
			*tag_len += BLOCKSIZE;
		}

		AES_ENCRYPT3(block1, block2, block3, aes_round_keys);

		block1 = veorq_u8(block1, delta_c1);
		block2 = veorq_u8(block2, delta_c2);
		block3 = veorq_u8(block3, delta_c3);

		STORE_BLOCK(out, block1);
		STORE_BLOCK(out + BLOCKSIZE, block2);
		STORE_BLOCK(out + (2 * BLOCKSIZE), block3);

		in += 3 * BLOCKSIZE;
		out += 3 * BLOCKSIZE;
		remaining -= 3 * BLOCKSIZE;
		iteration_counter += 3;
	}

	delta_m = delta_m3;
	delta_c = delta_c3;

    // finish up the remaining blocks
	while(remaining > BLOCKSIZE)
	{
		delta_m = gf_mul2(delta_m);
		
		block = LOAD_BLOCK(in);
		
		checksum = veorq_u8(checksum, block);
		
		block = veorq_u8(block, delta_m);

		AES_ENCRYPT(block, aes_round_keys);

		delta_c = gf_mul2(delta_c);

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

	// handle remaining bytes
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
		AES_ENCRYPT(tag, aes_round_keys);
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
    // prepare variables
	uint8x16_t checksum = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8x16_t w, w_tmp;
	uint8x16_t block1, block2, block3, block;
	uint8x16_t aes_encryption_keys[11];
	uint8x16_t aes_decryption_keys[11];
	uint8x16_t delta_m1, delta_m2, delta_m3, delta_m;
	uint8x16_t delta_c1, delta_c2, delta_c3, delta_c;
	uint8x16_t L = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	uint8x16_t w_tag;
	
    // pointers to reference in/output data
	const uint8_t* in = ciphertext;
	uint8_t* out = message;
	uint8_t* tag_in = tags;
	uint64_t remaining = *m_len = len - BLOCKSIZE;
	uint32_t i;
	uint8_t buf[BLOCKSIZE] = { 0 };
	uint64_t iteration_counter = 3;
	uint8_t itag;

	if (len < BLOCKSIZE)
	{
		// -1 => invalid size of ciphertext
		return -1;
	}

    // generate encryption keys used to calculate the MAC and to derive the decryption keys
	SET_ENCRPTION_KEYS(key, aes_encryption_keys);
	SET_DECRPTION_KEYS(aes_encryption_keys, aes_decryption_keys);
	
	AES_ENCRYPT(L, aes_encryption_keys);
	delta_m3 = L;
	delta_c3 = gf_mul3(gf_mul3(L));

    // calculate MAC
	w = mac(vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(npub), ((uint64x1_t){0x007F800000000000}))), associated_data, data_len, L, aes_encryption_keys);

    // main decryption loop (in parallel)
	while (remaining > 3 * BLOCKSIZE) {
		itag = iteration_counter % 127;

		delta_c1 = gf_mul2(delta_c3);
		delta_c2 = gf_mul2(delta_c1);
		delta_c3 = gf_mul2(delta_c2);

		delta_m1 = gf_mul2(delta_m3);
		delta_m2 = gf_mul2(delta_m1);
		delta_m3 = gf_mul2(delta_m2);

		block1 = LOAD_BLOCK(in);
		block2 = LOAD_BLOCK(in + BLOCKSIZE);
		block3 = LOAD_BLOCK(in + (2 * BLOCKSIZE));

        // process the intermediate tag
		switch (itag)
		{
			case 2: // tag "after" block1
				delta_c1 = delta_c2;
				delta_c = delta_c2;
				delta_c2 = delta_c3;
				delta_c3 = gf_mul2(delta_c3);
				break;
			case 1: // tag "after" block2
				delta_c2 = delta_c3;
				delta_c = delta_c3;
				delta_c3 = gf_mul2(delta_c3);
				break;
			case 0: // tag "after" block3
				delta_c3 = gf_mul2(delta_c3);
				delta_c = delta_c3;
				break;
			default:
				break;
		}


		block1 = veorq_u8(block1, delta_c1);
		block2 = veorq_u8(block2, delta_c2);
		block3 = veorq_u8(block3, delta_c3);

		AES_DECRYPT3(block1, block2, block3, aes_decryption_keys);

		RHO_INVERSE_INPLACE(block1, w, w_tmp); if (itag == 2) w_tag = w;
		RHO_INVERSE_INPLACE(block2, w, w_tmp); if (itag == 1) w_tag = w;
		RHO_INVERSE_INPLACE(block3, w, w_tmp); if (itag == 0) w_tag = w;

		// verify intermediate tag
		if (itag <= 2)
		{
			uint8x16_t tag = LOAD_BLOCK(tag_in);
			tag = veorq_u8(tag, delta_c);
			AES_DECRYPT(tag, aes_decryption_keys);
			if (!EQUALS(tag, w_tag))
			{
				return -5;
			}
			tag_in += BLOCKSIZE;
		}

		AES_DECRYPT3(block1, block2, block3, aes_decryption_keys);

		block1 = veorq_u8(block1, delta_m1);
		block2 = veorq_u8(block2, delta_m2);
		block3 = veorq_u8(block3, delta_m3);

		checksum = veorq_u8(checksum, block1);
		checksum = veorq_u8(checksum, block2);
		checksum = veorq_u8(checksum, block3);
		
		STORE_BLOCK(out, block1);
		STORE_BLOCK(out + BLOCKSIZE, block2);
		STORE_BLOCK(out + (2 * BLOCKSIZE), block3);

		in += 3 * BLOCKSIZE;
		out += 3 * BLOCKSIZE;
		remaining -= 3 * BLOCKSIZE;
		iteration_counter += 3;
	}


	delta_m = delta_m3;
	delta_c = delta_c3;

    // decrypt remaining blocks (at max 2)
	while (remaining > BLOCKSIZE) {
		delta_c = gf_mul2(delta_c);
		delta_m = gf_mul2(delta_m);

		// verify tag
		block = LOAD_BLOCK(in);

		block = veorq_u8(block, delta_c);

		AES_DECRYPT(block, aes_decryption_keys);

		if (iteration_counter % 127 == 0)
		{		
			delta_c = gf_mul2(delta_c);
			uint8x16_t tag = LOAD_BLOCK(tag_in);
			tag = veorq_u8(tag, delta_c);
			AES_DECRYPT(tag, aes_decryption_keys);
			if (!EQUALS(tag, w))
			{
				return -5;
			}
			tag_in += BLOCKSIZE;
		}

		RHO_INVERSE_INPLACE(block, w, w_tmp);
		
		AES_DECRYPT(block, aes_decryption_keys);
		
		block = veorq_u8(block, delta_m);
		
		checksum = veorq_u8(checksum, block);
		
		STORE_BLOCK(out, block);

		in += BLOCKSIZE;
		out += BLOCKSIZE;
		remaining -= BLOCKSIZE;
		iteration_counter++;
	}

    // decrypt the last few bytes

	delta_m = gf_mul7(delta_m);
	delta_c = gf_mul7(delta_c);


	if (remaining < BLOCKSIZE) {
		delta_m = gf_mul7(delta_m);
		delta_c = gf_mul7(delta_c);
	}

	block = LOAD_BLOCK(in);
	block = veorq_u8(block, delta_c);
	AES_DECRYPT(block, aes_decryption_keys);

	/* (X,W') = rho^-1(block, W) */
	RHO_INVERSE_INPLACE(block, w, w_tmp);

	AES_DECRYPT(block, aes_decryption_keys);
	block = veorq_u8(block, delta_m);
	/* block now contains M[l] = M[l+1] */
	
	checksum = veorq_u8(checksum, block);
	/* checksum now contains M*[l] */
	in += BLOCKSIZE;
	
	/* output last (maybe partial) plaintext block */
	
	STORE_BLOCK(buf, checksum);
	
	memcpy(out, buf, remaining);

	if (iteration_counter % 127 == 0)
	{		
		delta_c = gf_mul2(delta_c);
		uint8x16_t tag = LOAD_BLOCK(tag_in);
		tag = veorq_u8(tag, delta_c);
		AES_DECRYPT(tag, aes_decryption_keys);
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
	AES_ENCRYPT(block, aes_encryption_keys);
	
	/* (Y,W') = rho(block, W) */
	RHO_INPLACE(block, w, w_tmp);

	AES_ENCRYPT(block, aes_encryption_keys);
	block = veorq_u8(block, delta_c);
	/* block now contains C'[l+1] */


    // verify end tag (same as colm 0)
	STORE_BLOCK(buf, block);
	if (memcmp(in, buf, remaining) != 0) {
		return -2;
	}

	if (remaining < 16) {
		STORE_BLOCK(buf, checksum);

        // verify padding scheme
		if (buf[remaining] != 0x80) {
			return -3;
		}
		// remining bytes have to be zero
		for (i = remaining+1; i < 16; i++) {
			if (buf[i] != 0) {
				return -4;
			}
		}
	}

	return 0;
}
