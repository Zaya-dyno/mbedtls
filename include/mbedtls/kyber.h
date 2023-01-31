/**
 * \file crystal.h
 *
 * \brief This file provides an API for the Crystal public-key cryptosystem.
 *
 * The Crystal public-key cryptosystem is getting standardized
 */

#ifndef MBEDTLS_CRYSTAL_H
#define MBEDTLS_CRYSTAL_H

/*
 * Configuration of constants
 */


#define MBEDTLS_CRYSTAL_KYBER_N 256
#define MBEDTLS_CRYSTAL_KYBER_Q 3329
#define MBEDTLS_CRYSTAL_KYBER_ETA2 2
#define MBEBTLS_CRYSTAL_DILITHIUM_Q 8380417

#define MBEDTLS_CRYSTAL_KYBER_XOF_BLOCKBYTES 64

#define MBEDTLS_CRYSTAL_KYBER_SIZE_GEN_MATRIX MBETLS_CRYSTAL_KYBER_N * 3 / 2 + 2

#define MBEDTLS_CRYSTAL_KYBER_SYMBYTES 32 // hash and seed size
#define MBEDTLS_CRYSTAL_KYBER_SSBYTES 32 // shared key size

#define MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_KEY \
       (MBEDTLS_CRYSTAL_KYBER_K * MBEDTLS_CRYSTAL_KYBER_N * 12)/8

#define MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_SKEY MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_KEY

#define MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_PKEY \
        (MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_KEY + MBEDTLS_CRYSTAL_KYBER_SYMBYTES);

#define MBEDTLS_CRYSTAL_KYBER_SIZE_PACKED_U \
       (MBEDTLS_CRYSTAL_KYBER_N * MBEDTLS_CRYSTAL_KYBER_D_U)
#define MBEDTLS_CRYSTAL_KYBER_SIZE_PACKED_V \
       (MBEDTLS_CRYSTAL_KYBER_K * MBEDTLS_CRYSTAL_KYBER_N * MBEDTLS_CRYSTAL_KYBER_D_V)
#define MBEDTLS_CRYSTAL_KYBER_SIZE_PACKED_CT \
       (MBEDTLS_CRYSTAL_KYBER_SIZE_PACKED_U + MBEDTLS_CRYSTAL_KYBER_SIZE_PACKED_V)

#if defined(MBEDTLS_CRYSTAL_KYBER512)
#define MBEDTLS_CRYSTAL_KYBER_K 2
#define MBEDTLS_CRYSTAL_KYBER_ETA1 3
#define MBEDTLS_CRYSTAL_KYBER_D_U 10
#define MBEDTLS_CRYSTAL_KYBER_D_V 4
#elif defined(MBEDTLS_CRYSTAL_KYBER768)
#define MBEDTLS_CRYSTAL_KYBER_K 3
#define MBEDTLS_CRYSTAL_KYBER_ETA1 2
#define MBEDTLS_CRYSTAL_KYBER_D_U 10
#define MBEDTLS_CRYSTAL_KYBER_D_V 4
#elif defined(MBEDTLS_CRYSTAL_KYBER1024)
#define MBEDTLS_CRYSTAL_KYBER_K 4
#define MBEDTLS_CRYSTAL_KYBER_ETA1 2
#define MBEDTLS_CRYSTAL_KYBER_D_U 11
#define MBEDTLS_CRYSTAL_KYBER_D_V 5
#else
#define MBEDTLS_CRYSTAL_KYBER_K 3
#define MBEDTLS_CRYSTAL_KYBER_ETA1 2
#define MBEDTLS_CRYSTAL_KYBER_D_U 10
#define MBEDTLS_CRYSTAL_KYBER_D_V 4
#endif


#if MBEDTLS_CRYSTAL_KYBER_ETA1 == 2
#define GET_POLY_FROM_NOISE_ETA1 cbd_2
#elif MBEDTL_CRYSTAL_KYBER_ETA1 == 3
#define GET_POLY_FROM_NOISE_ETA1 cbd_3
#endif

#define GET_POLY_FROM_NOISE_ETA2 cbd_2

/* 
 * Crystal Error codes ( Need to give correct error code)
 */
/** Bad input parameters to function. */
#define MBEDTLS_ERR_CRYSTAL_BAD_INPUT_DATA                    -0x5080
/** Input data contains invalid padding and is rejected. */
#define MBEDTLS_ERR_CRYSTAL_INVALID_PADDING                   -0x5100
/** Something failed during generation of a key. */
#define MBEDTLS_ERR_CRYSTAL_KEY_GEN_FAILED                    -0x5180
/** Key failed to pass the validity check of the library. */
#define MBEDTLS_ERR_CRYSTAL_KEY_CHECK_FAILED                  -0x5200
/** The public key operation failed. */
#define MBEDTLS_ERR_CRYSTAL_PUBLIC_FAILED                     -0x5280
/** The private key operation failed. */
#define MBEDTLS_ERR_CRYSTAL_PRIVATE_FAILED                    -0x5300
/** The output buffer for decryption is not large enough. */
#define MBEDTLS_ERR_CRYSTAL_OUTPUT_TOO_LARGE                  -0x5400
/** The random generator failed to generate non-zeros. */
#define MBEDTLS_ERR_CRYSTAL_RNG_FAILED                        -0x5480

/**
 * \brief    The Crystal Kyber context structure
 */
typedef struct mbedtls_crystal_kyber_context
{
}
mbedtsl_crystal_kyber_context

/**
 * \brief    The Crystal Dilithium context structure
 */
typedef struct mbedtls_crystal_dilithium_context
{
}
mbedtsl_crystal_dilithium_context

/**
 * \brief          This function initializes an Crystal context.
 *
 * \param ctx      The Crystal context to initialize. This must not be \c NULL.
 */
void mbedtls_crystal_init( mbedtls_crystal_context *ctx );

#ifdef __cplusplus
extern "C" {
#endif


#define MBEDTLS_CRYSTAL_SIGN        1 /**< Identifier for CRYSTAL signature operations. */
#define MBEDTLS_CRYSTAL_CRYPT       2 /**< Identifier for CRYSTAL encryption and decryption operations. */

#ifdef __cplusplus
}
#endif

#endif /* crystal.h */
