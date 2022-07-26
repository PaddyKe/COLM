# COLM - Authenticated Encryption Algorithm
Pipelined low-level implementation of COLM for ARM-based systems

Security informtaion:
COLM is a relatively new encryption algorithm. It participated in the CEASAR contest. It has been verified and proofed for security.
However, as COLM is only a few years only, security scientists haven't had the opportunity to verify those claims as extensively as with older algorithms. Moreover, COLM has not been standardized (yet). Until then, I would recommend not using this algorithm for productive applications.
Additionally, this implementation is provided as is. I will not take any responsibilities for any implementation bugs or algorithms errors.

## Overview
COLM is a mode of operation of AES. It is one of the winners of the [ceasar competition for authenticated encryption algorithms](https://competitions.cr.yp.to/caesar.html).
COLM is an authenticated encryption algorithm (like AES-GCM) with the advantave of nonce reuse resistance. That means that it security guarantees hold up even if the nove will be reused.

In addition to that COLM can also guarantee the same security level of the below used block cipher. In the here implemented version of COLM, AES-128 was used as building block. Other block cipher can be used for COLM, however, it was originally built arrount AES.

## COLM in details
COLM can be instantiated in multiple ways. In this implementaiton only the two most common implementation were implemented (COLM0 and COLM127).
The base algorithm of both implementations is basically the same. The difference lies in the output of the algorithms.
While COLM0 produces an AES-GCM-like output (ciphertext with 16 byte tag), COLM127 will produce - additionally to that - intermediate tags.
The intermediate tags can be thought of basically exactly the same as the "end-tag" in COLM0 or AES-GCM only that they are generated during the encryption (every 127 blocks or 2032 bytes).
Those intermediate tags can be used to detect manipulation to the ciphertext earlier in the decryption phase. If a modification has taken place only up to 2031 bytes need to be checked before the algorithm terminates and reports the error.

On contrast to that COLM0 or AES-GCM need to decrypti the message completely before the tag can be verified.

### More information on COLM
- [Offitial Spec](https://competitions.cr.yp.to/round3/colmv1.pdf)
- [Security of COLM](https://competitions.cr.yp.to/round3/colm-addendum.pdf)


## Implementation
The implementation of COLM took place in the context of a bachelor thesis at the [Philipps University of Marburg](https://uni-marburg.de) at the [department for computer science](https://www.uni-marburg.de/de/fb12). The target of the thesis was to evaluate recent cryptographic algorithms (this also contains other block ciphers, and algorithms to calculate message authentication codes) on ARM based systems.

To do that, I've implemented COLM (and the other algorithms) as efficient as possible and evaluated the performance. The performance of cryptographic algorithms can be compared using the number of cycles required to encrypt/decrypto/MAC one byte of data.
To implement an COLM effitiently, I've made use of ARMs neon extention - a vector extension in the ARM standard which makes it possible to perform calculations on multiple values at once.

Independent of the instantiation of COLM, I've made two different implementations. The first one is a regular implementation. The second one is a parallelized implementation making use of the processor pipeline. The pipeline depths of ARM CPUs is 3. (That explaines why every instruction was repeated three times.) This leads to a performance improvement of almost three times.

The result of my COLM implementation can be found in my [bachelor thesis](Thesis.pdf) (unfortunately only in german).

## Link Collection regarding COLM
- COLM paper: https://competitions.cr.yp.to/round3/colmv1.pdf
- COLM Addendum (security proofes): https://competitions.cr.yp.to/round3/colm-addendum.pdf
- Overview of the CAESAR submissions: https://competitions.cr.yp.to/caesar-submissions.html
- Website of my supervisor Elmar Tischhauser: https://www.tischhauser.org/elmar/ 
