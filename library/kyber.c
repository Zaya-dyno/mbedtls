#include "common.h"

#if defined(MBEDTLS_CRYSTAL_C)

#include "mbedtls/kyber.h"
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

int parse(unsigned int *buf, size_t buf_len, poly *a_ntt,size_t * size){
	size_t i;
    int d_1,d_2;
	i = 0;

	while ( *size < MBEDTL_CRYSTAL_KYBER_N && i + 2 < buf_len){
		d_1 = buf[i] + 256 * (buf[i+1] % 16);
		d_2 = buf[i+1] / 16 + 16 * buf[i+2];

		if (d_1 < q) {
			a_ntt->coeffs[*size] = d_1;
			*size++;
		}
		if (d_2 < q && *size < n){
			a_ntt->coeffs[*size] = d_2;
			*size++;
		}
		i += 3;
	}
}

int cpapke_shake_128(mbedtls_sha3_context *ctx,unsigned char *alpha,unsigned char i, unsigned char j){
    unsigned char buf[MBEDTLS_CRYSTAL_KYBER_SYMBYTES + 2];
    unsigned char *nonce;

    nonce = buf + MBEDTLS_CRYSTAL_KYBER_SYMBYTES;
    memcpy(buf,alpha,MBEDTL_CRYSTAL_KYBER_SYMBYTES);
    *nonce = i;
    nonce++;
    *nonce = j;
    mbedtls_sha3_update(ctx,buf, MBEDTLS_CRYSTAL_KYBERS_SYMBYTES + 2);
}

int create_matrix(int transposed, poly_matrix *A, unsigned char * alpha){
	mbedtls_sha3_context ctx;
    unsigned char i,j,u;
    unsigned char buf[MBEDTLS_CRYSTAL_KYBER_SIZE_GEN_MATRIX];
    int size,off;

    mbedtls_sha3_init(&ctx);

	for (i = 0; i < MBEDTLS_CRYSTAL_KYBER_K; i++){
		for (j = 0; j < MBEDTLS_CRYSTAL_KYBER_K; j++){
            size = 0;
			mbedtls_sha3_starts(&ctx, MBEDTLS_SHA3_SHAKE128);

            if (transposed){
				cpapke_shake_128(&ctx,alpha,i,j);
			} else {
				cpapke_shake_128(&ctx,alpha,j,i);
			}

            mbedtls_sha3_finish(&ctx, buf, MBEDTLS_CRYSTAL_KYBER_SIZE_GEN_MATRIX);


            parse(buf,MBEDTLS_CRYSTAL_KYBER_SIZE_GEN_MATRIX, &A->col[i]->vec[j], &size);
            
            off = MBEDTLS_CRYSTAL_KYBER_SIZE_GEN_MATRIX % 3;
            while (size < MBEDTLS_CRYSTAL_KYBER_N){
                for(u = 0; u < off; u++){
                    buf[u] = buf[MBEDTLS_CRYSTAL_KYBER_SIZE_GEN_MATRIX - 3 + u];
                }
                mbedtls_sha3_finish(&ctx, buf + off, MBEDTLS_CRYSTAL_KYBER_XOF_BLOCKBYTES);
                parse(buf,off + MBEDTLS_CRYSTAL_KYBER_XOF_BLOCKBYTES, &A->col[i]->vec[j], &size);
                off = (off + MBEDTLS_CRYSTAL_KYBER_XOF_BLOCK_BYTES) % 3;
            }
		}
	}
}


int cbd_2(unsigned char * in, poly * out) {
    unsigned char *hash[2 * 64];
    unsigned int i;

    mbedtls_sha3(MBEDTLS_SHA3_SHAKE256,
                 beta, MBEDTLS_CRYSTAL_KYBER_SYMBYTES + 1,
                 hash, 2 * 64);
    
    for ( i = 0; i < MBEDTLS_CRYSTAL_KYBER_N/2; i++){
        out->coeffs[2*i + 0] = (hash[i] >> 0 & 0x1) + (hash[i] >> 1 & 0x1) - \
                               (hash[i] >> 2 & 0x1) - (hash[i] >> 3 & 0x1);
        out->coeffs[2*i + 1] = (hash[i] >> 4 & 0x1) + (hash[i] >> 5 & 0x1) - \
                               (hash[i] >> 6 & 0x1) - (hash[i] >> 7 & 0x1);
    }
}

int cbd_3(unsigned char *in, poly * out) {
    unsigned int i,j;
    unsigned int32_t t;
    unsigned char *hash[3 * 64];

    mbedtls_sha3(MBEDTLS_SHA3_SHAKE256,
                 beta, MBEDTLS_CRYSTAL_KYBER_SYMBYTES + 1,
                 hash, 3 * 64);

    for ( i = 0; i < MBEDTLS_CRYSTAL_KYBER_N/4; i++){
        t  = hash[3*i + 0] << 0;
        t += hash[3*i + 1] << 8;
        t += hash[3*i + 2] << 16;
        for (j = 0; j < 4; j++){
            signed int sum = 0;
            for (z = 0; z < 3; z++){
                sum += ( t >> z ) & 0x1 - ( t >> 3 >> z ) & 0x1;
            }
            t = t >> 6;
            out->coeffs[4*i + j] = sum;
        }
    }
}


int pack_public_key(unsigned char * buf, polyvec* key, unsigned char * alpha) {
    pack_polyvec(buf,key);
    memcpy(buf+MBEDTLS_CRYSTAL_KYBER_SIZE_PACKED_KEY,alpha,MBEDTLS_CRYSTAL_KYBER_SYMBYTES);
}

int pack_secret_key(unsigned char * buf, polyvec* key) {
    pack_polyvec(buf,key);
}

int NTT(polyvec s) {
    for (int i = 0; i < MBEDTLS_CRYSTAL_KYBER_K; i++){
        ntt(s.vec[i])
    }
}

int cpapke_keygen(int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng,
                  unsigned char *pk,
                  unsigned char *sk)
{
	unsigned char random_buf[MBEDTLS_CRYSTAL_KYBER_SYMBYTES];
    unsigned char alpha_beta_nonce[MBEDTLS_CRYSTAL_KYBER_SYMBYTES*2 + 1];
    unsigned char *alpha = alpha_beta_nonce;
    unsigned char *beta  = alpha_beta_nonce + MBEDTLS_CRYSTAL_KYBER_SYMBYTES;
    unsigned char *nonce = alhpa_beta_nonce + MBEDTLS_CRYSTAL_KYBER_SYMBYTES*2;
    poly_matrix A;
    polyvec s;
    polyvec e;
    polyvec t;

	// Random 32 bytes
	f_rng( p_rng, random_buf, MBEDTLS_CRYSTAL_KYBER_SYMBYTES);
	//  use sha3-512 to produce 2 32 bytes alpha beta
    mbedtls_sha3( MBEDTLS_SHA3_512,random_buf, MBEDTLS_CRYSTAL_KYBER_SYMBYTES,
                 alpha_beta, MBEDTLS_CRYSTAL_KYBER_SYMBYTES * 2)

	create_matrix(0,A,alpha);

	for (i = 0; i < MBEDTLS_CRYSTAL_KYBER_K; i++){
        GET_POLY_FROM_NOISE_ETA1(beta,&s->vec[i]);
	    *nonce = *nonce + 1;
	}


	for (i = 0; i < MBEDTLS_CRYSTAL_KYBER_K; i++){
        GET_POLY_FROM_NOISE_ETA2(beta,&e->vec[i]);
	    *nonce = *nonce + 1;
	}

	polyvec_ntt(&s);
    polyvec_ntt(&e);

    for(i=0;i<KYBER_K;i++) {
        polyvec_pointwise_acc_montgomery(&t.vec[i], &A.col[i], &s);
        poly_tomont(&t.vec[i]);
    }

    polyvec_add(&t,&e,&t);
    polyvec_reduce(&t);
    polyvec_reduce(&s);

	pack_public_key(pk,&t,alpha);
    pack_secret_key(sk,&s);
}

int pack_ciphertext(unsigned char *ct, polyvec * u, poly *v){
    compress_polyvec(ct,u);
    ct += MBEDLTS_CRYSTAL_KYBER_SIZE_PACKED_U;
    compress_poly(ct,v);
}

int unpack_ciphertext(unsigned char *ct, polyvec * u, poly *v){
    decompress_polyvec(ct,u);
    ct += MBEDTLS_CRYSTAL_KYBER_SIZE_PACKED_U;
    decompress_poly(ct,v);
}

int cpapke_enc(unsigned char *pk,
               unsigned char *m,
               unsigned char *random_bytes,
               unsigned char *ct)
{
	unsigned char random_buf[MBEDTLS_CRYSTAL_KYBER_SYMBYTES + 1];
    unsigned char *alpha = pk + MBEDTLS_CRYSTAL_KYBER_SIZE_PACKED_KEY;
    poly_matrix A;
    polyvec e_1;
    polyvec r;
    poly e_2,k;
    unsigned char * nonce = random_buf + MBEDTLS_CRYSTAL_KYBER_SYMBYTES;

    *nonce = 0;
    memcpy(random_buf, random_bytes, MBEDTLS_CRYSTAL_KYBER_SYMBYTES);

    poly_frommsg(&k, m)
	unpack_polyvec(pk,&t);
	create_matrix(1,&A_T,alpha);

	for (i = 0; i < MBEDTLS_CRYSTAL_KYBER_K; i++){
        GET_POLY_FROM_NOISE_ETA1(random_buf,&r->vec[i]);
	    *nonce = *nonce + 1;
	}
	
	for (i = 0; i < MBEDTLS_CRYSTAL_KYBER_K; i++){
        GET_POLY_FROM_NOISE_ETA2(random_buf,&e_1->vec[i]);
	    *nonce = *nonce + 1;
	}

    GET_POLY_FROM_NOISE_ETA2(random_buf,&e_2);
	polyvec_ntt(&r);
    
    for(i=0;i<KYBER_K;i++) {
        polyvec_pointwise_acc_montgomery(&u.vec[i], &A_T.col[i], &r_ntt);
        poly_tomont(&u.vec[i]);
    }
    
    polyvec_intt(&u);
    polyvec_add(&u,&e_1,&u);

    polyvec_pointwise_acc_montgomery(&v,&t,&r);
    polyvec_intt(&v)
    polytomont(&v);
    poly_add(&v,&e_2,&v);
    poly_add(&v,&v,&k);

	pack_ciphertext(ct,u,v);
}

int cpapke_dec(unsigned int *m, unsigned char * sk,unsigned char * ct){
    polyvec s,u;
    poly v;
    poly t;

    unpack_ciphertext(ct,&u,&v);
	unpack_poly(sk,&s);
    polyvec_ntt(&u);
    polyvec_pointwise_acc_montgomery(&t,&s,&u);
    poly_invntt_tomont(&t);
    poly_sub(&t,&v,&t);
    poly_reduce(&t);

    poly_tomsg(m,&t)
}

int ccakem_keygen(int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng,
                  unsigned char *pk,
                  unsigned char *sk)
{
    unsigned char random_buf[MBEDTLS_CRYSTAL_KYBER_SYMBYTES];
    unsigned char pk_sha[MBEDTLS_CRYSTAL_KYBER_SYMBYTES];

    f_rng( p_rng, random_buf, MBEDTLS_CRYSTAL_KYBER_SYMBYTES);

    cpapke_keygen(f_rng,p_rng,pk,sk);

    sk += MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_SKEY;

    memcpy(sk,pk,MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_PKEY);

    sk += MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_PKEY;

    mbedtls_sha3(MBEDTLS_SHA3_256, pk, MBEDTLS_CRYSTAL_KYBER_SIZE_PACKED_PKEY,
                 pk_sha, MBEDTLS_CRYSTAL_KYBER_SYMBYTES);

    memcpy(sk,pk_sha,MBEDTLS_CRYSTAL_KYBER_SYMBYTES);

    sk += MBEDTLS_CRYSTAL_KYBER_SYMBYTES;

    memcpy(sk,random_buf,MBEDTLS_CRYSTAL_KYBER_SYMBYTES);
}

int ccakem_enc(int (*f_rng)(void *, unsigned char *, size_t),
               void *p_rng,
               unsigned char *pk,
               unsigned char *ct,
               unsigned char *shared_key,
               size_t length)
{
    unsigned char c[MBEDTLS_CYRSTAL_KYBER_SIZE_ENCODED_SKEY];
    unsigned char buf[MBEDTLS_CRYSTAL_KYBER_SYMBYTES*2];
    unsigned char k_r[MBEDTLS_CRYSTAL_KYBER_SYMBYTES*2];
    unsigned char *k = k_r;
    unsigned char *r = k_r + MBEDTLS_CRYSTAL_KYBER_SYMBYTES;
    f_rng( p_rng, buf, MBEDTLS_CRYSTAL_KYBER_SYMBYTES);
    
    mbedtls_sha3(MBEDTLS_SHA3_256, buf, MBEDTLS_CRYSTAL_KYBER_SYMBYTES,
                 buf, MBEDTLS_CRYSTAL_KYBER_SYMBYTES);

    mbedtls_sha3(MBEDTLS_SHA3_256, pk, MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_PKEY,
                 buf + MBEDTLS_CRYSTAL_KYBER_SYMBYTES, MBEDTLS_CRYSTAL_KYBER_SYMBYTES);
    
    mbedtls_sha3(MBEDTLS_SHA3_512, k_r, MBEDTLS_CRYSTAL_KYBER_SYMBYTES * 2,
                 buf, MBEDTLS_CRYSTAL_KYBER_SYMBYTES * 2);

	cpapke_enc(pk,buf,r,ct);

    mbedtls_sha3(MEBDTLS_SHA3_256, ct, MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_SKEY,
                 buf, MEBDTLS_CRYSTAL_KYBER_CRYSTAL_SYMBYTES);
    mbedtls_sha3(MBEDTLS_SHA3_SHAKE256, k_r, MBEDTLS_CRYSTAL_KYBER_SYMBYTES * 2,
                 shared_key, length);
}

int ccakem_dec(unsigned char *ct,
               unsigned char *sk,
               unsigned char *shared_key,
               size_t length){
    unsigned char * pk = sk + MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_SKEY;
    unsigned char * h = pk + MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_PKEY;
    unsigned char * z = h + MBEDTLS_CRYSTAL_KYBER_SYMBYTES;
    unsigned char m_h[MBEDTL_CRYSTAL_KYBER_SYMBYTES * 2];
    unsigned char k_r[MBEDTLS_CRYSTAL_KYBER_SYMBYTES * 2];
    unsigned char *k = k_r;
    unsigned char *r = k_r + MBEDTLS_CRYSTAL_KYBER_SYMBYTES;
    unsigned char *m = m_h;
    unsigned char *hash = m_h + MBEDTLS_CRYSTAL_KYBER_SYMBYTES;
    unsigned char c[MBEDTLS_CRYSTAL_KYBER_SIZE_PACKED_CT];
    unsigned char digest[MBEDTL_CRYSTAL_KYBER_SYMBYTES*2];

    cpapke_dec(m,sk,ct);

    memcpy(hash,h,MBEDTLS_CRYSTAL_KYBER_SYMBYTES);

    mbedtls_sha3(MBEDTLS_SHA3_512, m_h, MBEDTLS_CRYSTAL_KYBER_SYMBYTES * 2,
                 k_r, MBEDTLS_CRYSTAL_KYBER_SYMBYTES * 2);

    cpapke_enc(pk,m,r,c)

	if (memcmp(ct,c,MBEDTL_CRYSTAL_KYBER_SIZE_PACKED_CT)){
        memcpy(digest,k,MBEDTLS_CRYSTAL_KYBER_SYMBYTES);
	} else {
        memcpy(digest,z,MBEDTLS_CRYSTAL_KYBER_SYMBYTES);
	}

    mbedtls_sha3(MBEDTLS_SHA3_256, c, MBEDTLS_CRYSTAL_KYBER_SIZE_PACKET_CT,
                 digest + MBEDTLS_CRYSTAL_KYBER_SYMBYTES, MBEDTLS_CRYSTAL_SYMBYTES);

    mbedtls_sha3(MBEDTLS_SHA3_SHAKE256, k_r, MBEDTLS_CRYSTAL_KYBER_SYMBYTES * 2,
                 shared_key, length);
}

#endif /* MBEDTLS_CRYSTAL_C */
