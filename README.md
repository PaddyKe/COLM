# COLM
Pipelined lowlevel implementation of COLM for ARM-based systems

Security Informtaion:
COLM is an relatively new encryption algorithms. It participated in the CEASAR contenst. It has been verified and proofed for security.
However, as COLM is only a few years only, security scientist haven't had the opportunity to verify those claims as extensivly as with older algorithms. Moreover, COLM has not been standardized (yet). Until then, I would recommend not using this algorithms for productive applications.
Additionally, this implementation is provided as is. I will not take any responsibilities for any implementation bugs or algorithms errors.

## Overview
COLM is an mode of operation of AES. It is one of the winners of the [ceasar competition for authenticated encryption algorithms](https://competitions.cr.yp.to/caesar.html).
COLM is an authenticated encryption algorithms (like AES-GCM) with the advantave of nonce reuse resistance. That means that it security guarantees hold up even if the nove will be reused.

In addition to that COLM can also guarantee the same security level of the below used block cipher. In the here implemented version of COLM, AES-128 was used as building block. Other blockcipher can be used for COLM, however, it was originally built arrount AES.

## COLM in details
COLM can be instantiated in multiple ways. In this implementaiton only the two most common implementaiton were implemented (COLM0 and COLM127).
The base algorithm of both implementations is basically the same. The difference lies in the output of the algorithms.
While COLM0 produces an AES-GCM-like output (ciphertext with 16 byte tag), COLM127 will produce - additionally to that - intermediate tags.
The intermediate tags can be thought of basically exactly the same as the "end-tag" in COLM0 or AES-GCM only that they are generated during the encryption (every 127 blocks or 2032 bytes).
Those intermediate taks can be used to detect manipulation to the ciphertext earlier in the decryption phase. If an modification has taken place only up to 2031 bytes need to be checked before the algorithm terminates and reports the error.

On contrast to that COLM0 or AES-GCM need to decrypti the message completely before the tag can be verified.

### More information on COLM
- [Offitial Spec](https://competitions.cr.yp.to/round3/colmv1.pdf)
- [Security proofs of COLM](https://competitions.cr.yp.to/round3/colm-addendum.pdf)


## Implementation
The implementation of COLM took place in the context of a bachelor thesis at the [Philipps University of Marburg](https://uni-marburg.de) at the [department for computer science](https://www.uni-marburg.de/de/fb12). The target of the thesis was to evaluate recent cryptographic algorithms (this also contains other blockciphers, and algorithms to calculate message authentication codes) on ARM based systems.

To do that, I've implemented COLM (and the other algorithms) as effitient as possible and evaluated the performance. The performance of cryptographic algoithms can be compared using the number of cycles required to encrypt/decrypto/MAC one byte of data.
To implement an effitient algorithms I made use of ARM neon - a vector extension of the ARM  standard which makes it possible to perform calcualations of (in this case) bytes at once.

Independent of the instantiation of COLM, I've made two differnt implementations. The first one is a regular implementaiton. The second one is is a parallelized implementaiton making use of the processor pipeline. The pipeline depths of ARM CPUs is three. That explaines why every instruction was repeated three times. This lead to an performance improvement of almost three times.

The result of my COLM implementation can be found in my [bachelor thesis](Thesis.pdf) (unfortunately only in german).

## Link Collection regarding COLM
- COLM paper: https://competitions.cr.yp.to/round3/colmv1.pdf
- COLM Addendum (security proofes): https://competitions.cr.yp.to/round3/colm-addendum.pdf
- Overview of the CAESAR submissions: https://competitions.cr.yp.to/caesar-submissions.html
- Website of my supervisor Elmar Tischhauser: https://www.tischhauser.org/elmar/ 
