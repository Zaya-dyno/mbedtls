/* Code to generate zetas and zetas_inv used in the number-theoretic transform:

#define KYBER_ROOT_OF_UNITY 17

static const uint16_t tree[128] = {
  0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120,
  4, 68, 36, 100, 20, 84, 52, 116, 12, 76, 44, 108, 28, 92, 60, 124,
  2, 66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122,
  6, 70, 38, 102, 22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126,
  1, 65, 33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121,
  5, 69, 37, 101, 21, 85, 53, 117, 13, 77, 45, 109, 29, 93, 61, 125,
  3, 67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91, 59, 123,
  7, 71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127
};

void init_ntt() {
  unsigned int i, j, k;
  int16_t tmp[128];

  tmp[0] = MONT;
  for(i = 1; i < 128; ++i)
    tmp[i] = fqmul(tmp[i-1], KYBER_ROOT_OF_UNITY*MONT % KYBER_Q);

  for(i = 0; i < 128; ++i)
    zetas[i] = tmp[tree[i]];

  k = 0;
  for(i = 64; i >= 1; i >>= 1)
    for(j = i; j < 2*i; ++j)
      zetas_inv[k++] = -tmp[128 - tree[j]];

  zetas_inv[127] = MONT * (MONT * (KYBER_Q - 1) * ((KYBER_Q - 1)/128) % KYBER_Q) % KYBER_Q;
}

*/

const int16_t zetas[128] = {
  2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
  2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
  732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
  1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
  107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
  430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
  1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
  418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
  1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
  478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628
};

const int16_t zetas_inv[128] = {
  1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
  1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
  1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
  1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
  3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
  1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
  1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
  2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
  829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
  3127, 3042, 1907, 1836, 1517, 359, 758, 1441
};

static int16_t fqmul(int16_t a, int16_t b) {
  return montgomery_reduce((int32_t)a*b);
}

void ntt(int16_t r[256]) {
  unsigned int len, start, j, k;
  int16_t t, zeta;

  k = 1;
  for(len = 128; len >= 2; len >>= 1) {
    for(start = 0; start < 256; start = j + len) {
      zeta = zetas[k++];
      for(j = start; j < start + len; ++j) {
        t = fqmul(zeta, r[j + len]);
        r[j + len] = r[j] - t;
        r[j] = r[j] + t;
      }
    }
  }
}

void invntt(int16_t r[256]) {
  unsigned int start, len, j, k;
  int16_t t, zeta;

  k = 0;
  for(len = 2; len <= 128; len <<= 1) {
    for(start = 0; start < 256; start = j + len) {
      zeta = zetas_inv[k++];
      for(j = start; j < start + len; ++j) {
        t = r[j];
        r[j] = barrett_reduce(t + r[j + len]);
        r[j + len] = t - r[j + len];
        r[j + len] = fqmul(zeta, r[j + len]);
      }
    }
  }

  for(j = 0; j < 256; ++j)
    r[j] = fqmul(r[j], zetas_inv[127]);
}

void poly_tomsg(unsigned int *m, poly * t) {

    poly_csubq(t)
    for(i=0;i<KYBER_N/8;i++) {
        msg[i] = 0;
        for(j=0;j<8;j++) {
            t = ((((uint16_t)t->coeffs[8*i+j] << 1) + MBEDTLS_CRYSTAL_KYBER_Q/2) \
                    /MBEDTLS_CRYSTAL_KYBER_Q) & 1;
            msg[i] |= t << j;
        }
    }
}

int polyvec_ntt(polyvec *r){
    for (int i = 0; i < MBEDTLS_CRYSTAL_KYBER_K; i++){
        ntt(*r.vec[i]);
    }
}

void polyvec_pointwise_acc_montgomery(poly *r,
                                      const polyvec *a,
                                      const polyvec *b)
{
      unsigned int i;
      poly t;

      poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
      for(i=1;i<KYBER_K;i++) {
        poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &t);
      }

      poly_reduce(r);
}

int unpack_polyvec(unsigned char *buf, polyvec *vec){
    unsigned int i;
    for(i=0;i<MBEDTLS_CRYSTAL_KYBER_K;i++){
        unpack_poly(buf,vec->vec[i]);
        buf += MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_KEY;
    }
}

int pack_polyvec(unsigned char * buf, polyvec *vec){
    unsigned int i;
    for(i=0;i<MBEDTLS_CRYSTAL_KYBER_K;i++){
        pack_poly(buf,vec->vec[i]);
        buf += MBEDTLS_CRYSTAL_KYBER_SIZE_ENCODED_KEY;
    }
}

int unpack_poly(unsigned char * buf, poly* poly){
    unsigned int i;
    for(i=0;i<MBEDTLS_CRYSTAL_KYBER_N/2;i++) {
        poly->coeffs[2*i + 0] =  buf[3*i + 0];
        poly->coeffs[2*i + 0] += (buf[3*i + 1] && 0xFF ) << 8;
        poly->coeffs[2*i + 1] =  buf[3*i + 1] >> 4;
        poly->coeffs[2*i + 1] += buf[3*i + 2] << 4;
    }
}

int pack_poly(unsigned char * buf, poly* poly) {
    unsigned int i;
    for(i=0;i<MBEDTLS_CRYSTAL_KYBER_N/2;i++){
        buf[3*i + 0] = poly->coeffs[2*i + 0];
        buf[3*i + 1] = poly->coeffs[2*i + 1] << 4 | poly->coeffs[i] >> 8;
        buf[3*i + 2] = poly->coeffs[2*i + 1] >> 4;
    }
}

void poly_basemul_montgomery(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  for(i=0;i<KYBER_N/4;i++) {
    basemul(&r->coeffs[4*i], &a->coeffs[4*i], &b->coeffs[4*i], zetas[64+i]);
    basemul(&r->coeffs[4*i+2], &a->coeffs[4*i+2], &b->coeffs[4*i+2],
            -zetas[64+i]);
  }
}


int16_t montgomery_reduce(int32_t a)
{
  int32_t t;
  int16_t u;

  u = a*QINV;
  t = (int32_t)u*KYBER_Q;
  t = a - t;
  t >>= 16;
  return t;
}

int16_t barrett_reduce(int16_t a) {
  int16_t t;
  const int16_t v = ((1U << 26) + KYBER_Q/2)/KYBER_Q;

  t  = (int32_t)v*a >> 26;
  t *= KYBER_Q;
  return a - t;
}

void polyvec_reduce(polyvec *a){
    unsigned int i;
    for(i=0;i<MBEDTLS_CRYSTAL_KYBER_K;i++){
        poly_reduce(&a->vec[i]);
    }
}

void poly_tomont(poly *r)
{
  unsigned int i;
  const int16_t f = (1ULL << 32) % MBEDTLS_CRYSTAL_KYBER_Q;
  for(i=0;i<MBEDTLS_CRYSTAL_KYBER_N;i++)
    r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i]*f);
}

void poly_reduce(poly *a){
    unsigned int i;
    for(i=0;i<MBEDTLS_CRYSTAL_KYBER_N;i++){
        a->coeffs[i] = barret_reduce(a->coeffs[i]);
    }
}

void basemul(int16_t r[2],
             const int16_t a[2],
             const int16_t b[2],
             int16_t zeta)
{
  r[0]  = fqmul(a[1], b[1]);
  r[0]  = fqmul(r[0], zeta);
  r[0] += fqmul(a[0], b[0]);

  r[1]  = fqmul(a[0], b[1]);
  r[1] += fqmul(a[1], b[0]);
}

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b){
    unsigned int i;
    for (i=0;i<MBEDTLS_CRYSTAL_KYBER_K;i++){
        poly_add(&r->vec[i],&a->vec[i],&b->vec[i]);
    }
}

void poly_add(poly *r, const poly *a, const poly *b)
{
  unsigned int i;
  for(i=0;i<MBEDTLS_CRYSTAL_KYBER_N;i++)
    r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

int compress_poly(unsigned char *buf, poly * v){
    unsigned int i;
#if MBEDTLS_CRYSTAL_KYBER_D_V == 4
    unsigned char t;
    for (i = 0; i < MBEDTLS_CRYSTAL_KYBER_N/2; i++){
        t = ((poly.coeffs[2*i + 0] << 4) + MBEDTLS_CRYSTAL_KYBER_Q/2 )\
                MBEDTLS_CRYSTAL_KYBER_Q & 0xF;
        t = t << 4;
        buf[i] = t | (((poly.coeffs[2*i + 1] << 4) + MBEDTLS_CRYSTAL_KYBER_Q/2 )\
                        MBEDTLS_CRYSTAL_KYBER_Q & 0xF);
    }
#elif MBEDTLS_CRYSTAL_KYBER_D_V == 5
    unsigned int j;
    unsigned char t[8];

    for (i = 0; i < MBEDTLS_CRYSTAL_KYBER_N/8; i++){
        for (j = 0; j < 8; j++){
            t[j] = ((poly.coeffs[8*i + j] << 5) + MBEDTLS_CRYSTAL_KYBER_Q/2 )\
                       MBEDTLS_CRYSTAL_KYBER_Q & 0x1F;
        }
        buf[i*5 + 0] = t[0] | (t[1] << 5);
        buf[i*5 + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
        buf[i*5 + 2] = (t[3] >> 1) | (t[4] << 4);
        buf[i*5 + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
        buf[i*5 + 4] = (t[6] >> 2) | (t[7] << 3);
    }
#endif
}

int compress_polyvec(unsigned char *buf,polyvec * u){
    unsigned int i,j,z;
#if MBEDTLS_CRYSTAL_KYBER_D_U == 10
    unsigned char t[4];

    for (i = 0; i < MBEDTLS_CRYSTAL_KYBER_K; i++){
        poly * poly = polyvec->vec[i];
        for (j = 0; j < MBEDTLS_CRYSTAL_KYBER_N/4; j++) {
            for (z = 0; z < 4; z++) {
                t[z] = (((uint32_t)poly.coeffs[4*j+z] << 10) + MBEDTLS_CRYSTAL_KYBER_Q/2 )\
                           MBEDTLS_CRYSTAL_KYBER_Q & 0x3FF;
            }
            buf[j*5 + 0] = t[0];
            buf[j*5 + 1] = (t[0] >> 8 ) | (t[1] << 2);
            buf[j*5 + 2] = (t[1] >> 6 ) | (t[2] << 4);
            buf[j*5 + 3] = (t[2] >> 4 ) | (t[3] << 6);
            buf[j*5 + 4] = (t[3] >> 2 );
        }
        buf += (MBEDTLS_CRYSTAL_KYBER_N * 5) / 4;
    }
#elif MBEDTLS_CRYSTAL_KYBER_D_U == 11
    unsigned char t[8];

    for (i = 0; i < MBEDTLS_CRYSTAL_KYBER_K; i++){
        poly * poly = polyvec->vec[i];
        for (j = 0; j < MBEDTLS_CRYSTAL_KYBER_N/8; j++) {
            for (z = 0; z < 8; z++) {
                t[z] = (((uint32_t)poly.coeffs[8*j+z] << 11) + MBEDTLS_CRYSTAL_KYBER_Q/2 )\
                           MBEDTLS_CRYSTAL_KYBER_Q & 0x7FF;
            }
            buf[j*11 + 0] = t[0];
            buf[j*11 + 1] = (t[0] >> 8) | (t[1] << 3);
            buf[j*11 + 2] = (t[1] >> 5) | (t[2] << 6); 
            buf[j*11 + 3] = t[2] >> 2;
            buf[j*11 + 4] = (t[2] >> 10 ) | (t[3] << 1); 
            buf[j*11 + 5] = (t[3] >> 7) | (t[4] << 4);
            buf[j*11 + 6] = (t[4] >> 4) | (t[5] << 7);
            buf[j*11 + 7] = t[5] >> 1;
            buf[j*11 + 8] = (t[5] >> 9) | (t[6] << 2);
            buf[j*11 + 9] = (t[6] >> 6) | (t[7] << 5);
            buf[j*11 + 10] = t[7] >> 3;
        }
        buf += (MBEDTLS_CRYSTAL_KYBER_N * 11) / 8;
    }
#endif
}


void poly_frommsg(poly *r, unsigned char *msg)
{
  unsigned int i,j;
  int16_t mask;

  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      mask = -(int16_t)((msg[i] >> j)&1);
      r->coeffs[8*i+j] = mask & ((KYBER_Q+1)/2);
    }
  }
}

int16_t csubq(int16_t a){
    a -= MBEDTLS_CRYSTAL_KYBER_Q;
    a += (a >> 15) & MBEDTLS_CRYSTAL_KYBER_Q;
    return a;
}

