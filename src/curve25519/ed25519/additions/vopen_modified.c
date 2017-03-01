#include <string.h>
#include "sc.h"
#include "ge.h"
#include "crypto_hash_sha512.h"
#include "crypto_verify_32.h"
#include "crypto_additions.h"
#include "crypto_sign.h"

int crypto_vsign_open_modified(
  unsigned char *m,
  const unsigned char *sm,unsigned long long smlen,
  const unsigned char *pk, const ge_p3* Bv
)
{
  ge_p3 Vneg, V, Aneg, A, c_V, c_A, h_Vneg, s_Bv;
  unsigned char h[32];
  unsigned char s[32];
  ge_p2 R;
  unsigned char hcheck[64];
  unsigned char vrf_output[64];
  int count;
  ge_p1p1 Rp1p1;
  ge_p3 Rv;
  ge_cached h_Vnegcached;

  if (smlen < 96) goto badsig;
  if (sm[63] & 224) goto badsig; /* strict parsing of h */
  if (sm[95] & 224) goto badsig; /* strict parsing of s */

  /* Load -A */
  if (ge_frombytes_negate_vartime(&Aneg,pk) != 0) goto badsig;

  /* Load -V, h, s */
  if (ge_frombytes_negate_vartime(&Vneg, sm) != 0) goto badsig;
  memmove(h, sm + 32, 32); 
  memmove(s, sm + 64, 32); 
  if (h[31] & 224) goto badsig; /* strict parsing of h */
  if (s[31] & 224) goto badsig; /* strict parsing of s */

  ge_neg(&A, &Aneg);
  ge_neg(&V, &Vneg);
  ge_scalarmult_cofactor(&c_A, &A);
  ge_scalarmult_cofactor(&c_V, &V);
  if (ge_isneutral(&c_A) || ge_isneutral(&c_V) || ge_isneutral(Bv))
    goto badsig;

  // R = (s*B) + (h * -A))
  ge_double_scalarmult_vartime(&R, h, &Aneg, s);

  // s * Bv
  ge_scalarmult(&s_Bv, s, Bv);

  // h * -V
  ge_scalarmult(&h_Vneg, h, &Vneg);

  // Rv = (sc * Bv) + (hc * (-V))
  ge_p3_to_cached(&h_Vnegcached, &h_Vneg);
  ge_add(&Rp1p1, &s_Bv, &h_Vnegcached);
  ge_p1p1_to_p3(&Rv, &Rp1p1);

  // Check h == SHA512(label(4) || A || V || R || Rv || M)
  m[0] = 0xFB;  // label 4
  for (count = 1; count < 32; count++)
    m[count] = 0xFF;
  memmove(m+32, pk, 32);
  ge_p3_tobytes(m+64, &V);
  ge_tobytes(m+96, &R);
  ge_p3_tobytes(m+128, &Rv);
  memmove(m+160, sm+96, smlen - 96);

  crypto_hash_sha512(hcheck, m, smlen + 64);
  sc_reduce(hcheck);

  if (crypto_verify_32(hcheck, h) == 0) {
    ge_p3_tobytes(m+32, &c_V);
    m[0] = 0xFA; // label 5
    crypto_hash_sha512(vrf_output, m, 64);
    memmove(m, vrf_output, 32);
    return 0;
  }

badsig:
  memset(m, 0, 32);
  return -1;
}
