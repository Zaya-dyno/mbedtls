#include "common.h"

#if defined(MBEDTLS_DILITHIUM_C)

#include "mbedtls/dilithium.h"
#include "rsa_alt_helpers.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "constant_time_internal.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/sha3.h"
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

int mbedtls_dilithium_gen(int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng,
                          unsigned char *pk,
                          unsigned char *sk)
{
    unsigned char rho_rhod_k[MBEDTLS_DILITHIUM_SYMBYTES * 4];
    unsigned char random_buf[MBEDTLS_DILITHIUM_SYMBYTES];
    unsigned char tr[MBEDTLS_DILITHIUM_SYMBYTES];
    unsigned char *rho,rhod,K;
    matrix A;
    polyvecl s1;
    polyveck s2,t1,t0;

    rho = rho_rhod_K;
    rhod = rho_rhod_K + MBEDTLS_DILITHIUM_SYMBYTES;
    K = rhod + MBEDTLS_DILITHIUM_DOUBLE_SYMBYTES;

    f_rng(p_rng, random_buf, MBEDTLS_DILITHIUM_SYMBYTES);

    mbedlts_sha3( MBEDTLS_SHA3_SHAKE256, random_buf, MBEDTLS_DILITHIUM_SYMBYTES,
                  rho_rhod_K, MBEDTLS_DILITHIUM_SYMBYTES * 4);

    expand_matrix(&A, rho);

    expand_s(&s1, &s2, rhod);

    polyvecl_ntt(&s1);
    polyvec_matrix_pointwise_montgomery(&t1, &A, &s1);
    polyveck_reduce(&t1);
    polyveck_invntt_tomont(&t1);

    /* Add error vector s2 */
    polyveck_add(&t1, &t1, &s2);

    polyveck_caddq(&t1);

    polyveck_power2round(&t1, &t0, &t1);
    pack_pk(pk, rho, &t1);

    mbedtls_sha3(MBEDTLS_SHA3_SHAKE256, pk, MBEDTLS_DILITHIUM_PACKED_PK,
                 tr, MBEDTLS_DILITHIUM_SYMBYTES);

    pack_sk(sk, rho, K, tr, &s1, &s2, &t0);
}

int mbedtls_dilithium_sign(int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng,
                  unsigned char *sk,
                  unsigned char *M,
                  size_t M_length)
{
    unsigned char rho_rhod_K[MBEDTLS_DILITHIUM_SYMBYTES * 4];
    unsigned char tr[MBEDTLS_DILITHIUM_SYMBYTES];
    unsigned char sigma[MBEDTLS_DILITHIUM_DOUBLE_SYMBYTES + MBEDTLS_DILITHIUM_SIZE_PACKED_W1];
    unsigned char *rho,rhod,K;
    unsigned char h;
    unsigned char k;
    matrix A;
    polyvecl s1,y,z;
    polyveck s2;
    
    rho = rho_rhod_K;
    rhod = rho_rhod_K + MBEDTLS_DILITHIUM_SYMBYTES;
    K = rhod + MBEDTLS_DILITHIUM_DOUBLE_SYMBYTES;
    
    unpack_sk(sk, rho, K, tr, &s1, &s2, &t0);

    expand_matrix(&A, rho);

    mbedtls_sha3_init(&ctx);
    mbedtls_sha3_start(&ctx, MBEDTLS_SHA3_SHAKE256);
    mbedtls_sha3_update(&ctx, tr, MBEDTLS_DILITHIUM_SYMBYTES);
    mbedtls_sha3_update(&ctx, M, M_length);
    mbedtls_sha3_finish(&ctx, sigma, MBEDTLS_DILITHIUM_DOUBLE_SYMBYTES);

    polyvecl_ntt(&s1);
    polyveck_ntt(&s2);
    polyveck_ntt(&t0);
    k = 0;
    h = 0;

    while( 1 ) {
        expand_mask(&y, rhod, k);
        
        polyvecl_ntt(&y);
        polyvec_matrix_pointwise_montgomery(&w, &A, &y);
        polyveck_reduce(&w);
        polyveck_invntt_tomont(&t1);

        highbits(&w1,&w);
        polyveck_pack_w1(sigma + MBEDTLS_DILITHIUM_SYMBYTES, &w1);

        mbedtls_sha3(MBEDTLS_SHA3_SHAKE256, sigma, MBEDTLS_DILIGHTIUM_SYMBYTES + MBEDLT_DILITHIUM_SIZE_PACKED_W1,
                     c_delta, MBEDTLS_DILITHIUM_DOUBLE_SYMBYTES);

        sample_in_ball(&c, &c_delta);

        z = y + c * s_1;

        r_0 = LowBits(w - c * s_2);

        if not (length(z) >= delta_1 - beta || length(r_0) >= delta_2 - beta) {
            h = MakeHint(-c * t_0, w - c * s_2 + c * t_0);
            if not ( length(c * t_0) > delta_2 || the # of 1’sin h is greater than ω)
                break;
        }
        k = k + l;
    }
    pack_sign(signature, c_delta, z, h);
}

int mbedtls_dilithium_verify(unsigned char * pk,
                             unsigned char * M, size_t M_len,
                             unsigned char * signature)
{
    unpack_sign(signature, c_delta, z, h);
    unpack_pk(pk, rho, t_1);

    expand_matrix(&A, rho);

    mbedtls_sha3(MBEDTLS_SHA3_SHAKE256, pk, MBEDTLS_DILITHIUM_PACKED_PK,
                 tr, MBEDTLS_DILITHIUM_SYMBYTES);
    
    mbedtls_sha3(MBEDTLS_SHA3_SHAKE256, tr_M, MBEDTLS_DILITHIUM_PACKED_PK + M_len,
                 sigma, MBEDTLS_DILITHIUM_DOUBLE_SYMBYTES);

    sample_in_ball(&c, &c_delta);
    
    w1 = UseHint(h, Az - c * t1 * 2^d);

    return length(z) < gamma_1 - beta && c_delta = H(sigma || w_1) &&
           count_high_bits(h) =< omega;
}



#endif /* MBEDTLS_CRYSTAL_C */
