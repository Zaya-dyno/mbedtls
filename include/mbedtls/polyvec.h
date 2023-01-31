
const int16_t zetas[128];

const int16_t zetas_int[128];

void ntt(int16_t poly[256]);

void ntt_inv(int16_t poly[256]);

typedef struct {
    int16_t coeffs[MBEDTLS_CRYSTAL_KYBER_N];
} poly;

typedef struct {
    poly vec[MBEDTLS_CRYSTAL_KYBER_K];
} polyvec;

typedef struct {
    poly col[MBEDTLS_CRYSTAL_KYBER_K];
} poly_matrix;
