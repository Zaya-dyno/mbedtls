/**
 * \file crystal.h
 *
 * \brief This file provides an API for the Crystal public-key cryptosystem.
 *
 * The Crystal public-key cryptosystem is getting standardized
 */

#ifndef MBEDTLS_KYBER_H
#define MBEDTLS_KYBER_H

/*
 * Configuration of constants
 */


#define MBEDTLS_KYBER_N 256
#define MBEDTLS_KYBER_Q 3329
#define MBEDTLS_KYBER_ETA2 2
#define MBEBTLS_DILITHIUM_Q 8380417

#define MBEDTLS_KYBER_XOF_BLOCKBYTES 64

#define MBEDTLS_KYBER_SIZE_GEN_MATRIX MBETLS_KYBER_N * 3 / 2 + 2

#define MBEDTLS_KYBER_SYMBYTES 32 // hash and seed size
#define MBEDTLS_KYBER_SSBYTES 32 // shared key size

#define MBEDTLS_KYBER_SIZE_ENCODED_KEY \
       (MBEDTLS_KYBER_K * MBEDTLS_KYBER_N * 12)/8

#define MBEDTLS_KYBER_SIZE_ENCODED_SKEY MBEDTLS_KYBER_SIZE_ENCODED_KEY

#define MBEDTLS_KYBER_SIZE_ENCODED_PKEY \
        (MBEDTLS_KYBER_SIZE_ENCODED_KEY + MBEDTLS_KYBER_SYMBYTES);

#define MBEDTLS_KYBER_SIZE_PACKED_U \
       (MBEDTLS_KYBER_N * MBEDTLS_KYBER_D_U)
#define MBEDTLS_KYBER_SIZE_PACKED_V \
       (MBEDTLS_KYBER_K * MBEDTLS_KYBER_N * MBEDTLS_KYBER_D_V)
#define MBEDTLS_KYBER_SIZE_PACKED_CT \
       (MBEDTLS_KYBER_SIZE_PACKED_U + MBEDTLS_KYBER_SIZE_PACKED_V)

#if defined(MBEDTLS_KYBER512)
#define MBEDTLS_KYBER_K 2
#define MBEDTLS_KYBER_ETA1 3
#define MBEDTLS_KYBER_D_U 10
#define MBEDTLS_KYBER_D_V 4
#elif defined(MBEDTLS_KYBER768)
#define MBEDTLS_KYBER_K 3
#define MBEDTLS_KYBER_ETA1 2
#define MBEDTLS_KYBER_D_U 10
#define MBEDTLS_KYBER_D_V 4
#elif defined(MBEDTLS_KYBER1024)
#define MBEDTLS_KYBER_K 4
#define MBEDTLS_KYBER_ETA1 2
#define MBEDTLS_KYBER_D_U 11
#define MBEDTLS_KYBER_D_V 5
#else
#define MBEDTLS_KYBER_K 3
#define MBEDTLS_KYBER_ETA1 2
#define MBEDTLS_KYBER_D_U 10
#define MBEDTLS_KYBER_D_V 4
#endif


#if MBEDTLS_KYBER_ETA1 == 2
#define GET_POLY_FROM_NOISE_ETA1 cbd_2
#elif MBEDTL_KYBER_ETA1 == 3
#define GET_POLY_FROM_NOISE_ETA1 cbd_3
#endif
#define GET_POLY_FROM_NOISE_ETA2 cbd_2

/* 
 * Kyber Error codes ( Need to give correct error code)
 */
/** Bad input parameters to function. */
#define MBEDTLS_ERR_KYBER_BAD_INPUT_DATA                    -0x4600
/** Input data contains invalid padding and is rejected. */
#define MBEDTLS_ERR_KYBER_INVALID_PADDING                   -0x4680
/** Something failed during generation of a key. */
#define MBEDTLS_ERR_KYBER_KEY_GEN_FAILED                    -0x4700
/** Key failed to pass the validity check of the library. */
#define MBEDTLS_ERR_KYBER_KEY_CHECK_FAILED                  -0x4780
/** The public key operation failed. */
#define MBEDTLS_ERR_KYBER_PUBLIC_FAILED                     -0x4800
/** The private key operation failed. */
#define MBEDTLS_ERR_KYBER_PRIVATE_FAILED                    -0x4880
/** The output buffer for decryption is not large enough. */
#define MBEDTLS_ERR_KYBER_OUTPUT_TOO_LARGE                  -0x4900
/** The random generator failed to generate non-zeros. */
#define MBEDTLS_ERR_KYBER_RNG_FAILED                        -0x4980

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief    The Crystal Kyber context structure
 */
typedef struct mbedtls_kyber_context {
    int hello;
} mbedtls_kyber_context;


/**
 * \brief          This function initializes an Crystal context.
 *
 * \param ctx      The Crystal context to initialize. This must not be \c NULL.
 */
void mbedtls_kyber_init( mbedtls_kyber_context *ctx );

int cpapke_keygen(int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng,
                  unsigned char *pk,
                  unsigned char *sk);

int cpapke_enc(unsigned char *pk,
               unsigned char *m,
               unsigned char *random_bytes,
               unsigned char *ct);

int cpapke_dec(unsigned int *m,
               unsigned char * sk,
               unsigned char * ct);

int ccakem_keygen(int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng,
                  unsigned char *pk,
                  unsigned char *sk);

int ccakem_enc(int (*f_rng)(void *, unsigned char *, size_t),
               void *p_rng,
               unsigned char *pk,
               unsigned char *ct,
               unsigned char *shared_key,
               size_t length);

int ccakem_dec(unsigned char *ct,
               unsigned char *sk,
               unsigned char *shared_key,
               size_t length);

#define MBEDTLS_CRYSTAL_SIGN        1 /**< Identifier for CRYSTAL signature operations. */
#define MBEDTLS_CRYSTAL_CRYPT       2 /**< Identifier for CRYSTAL encryption and decryption operations. */

#ifdef __cplusplus
}
#endif

#endif /* crystal.h */
