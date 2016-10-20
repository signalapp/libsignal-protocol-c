#include <string.h>
#include "sc.h"
#include "ge.h"
#include "crypto_hash_sha512.h"
#include "crypto_verify_32.h"
#include "crypto_additions.h"
#include "crypto_sign.h"

int crypto_usign_open_modified(
  unsigned char *m,unsigned long long *mlen,
  const unsigned char *sm,unsigned long long smlen,
  const unsigned char *pk, const ge_p3* Bu
)
{
  ge_p3 U;
  unsigned char h[64];
  unsigned char s[64];
  unsigned char strict[64];
  ge_p3 A;
  ge_p2 R;
  unsigned char hcheck[64];
  int count;

  if (smlen < 96) goto badsig;
  if (sm[63] & 224) goto badsig; /* strict parsing of h */
  if (sm[95] & 224) goto badsig; /* strict parsing of s */

  /* Load -A */
  if (ge_frombytes_negate_vartime(&A,pk) != 0) goto badsig;

  /* Load -U, h, s */
  ge_frombytes_negate_vartime(&U, sm);
  memset(h, 0, 64);
  memset(s, 0, 64);
  memmove(h, sm + 32, 32); 
  memmove(s, sm + 64, 32); 

  /* Insist that s and h are reduced scalars (strict parsing) */
  memcpy(strict, h, 64);
  sc_reduce(strict);
  if (memcmp(strict, h, 32) != 0)
    goto badsig;
  memcpy(strict, s, 64);
  sc_reduce(strict);
  if (memcmp(strict, s, 32) != 0)
    goto badsig;

  /* Reject U (actually -U) if small order */
  if (ge_is_small_order(&U))
    goto badsig;

  // R = sB + h(-A)
  ge_double_scalarmult_vartime(&R,h,&A,s);

  // Ru = sBu + h(-U)
  ge_p3 sBu, hU;

  // sBu
  ge_scalarmult(&sBu, s, Bu);

  // h(-U)
  ge_scalarmult(&hU, h, &U);

  // Ru = sBu + h(-U)
  ge_p1p1 Rp1p1;
  ge_p3 Ru;
  ge_cached hUcached;
  ge_p3_to_cached(&hUcached, &hU);
  ge_add(&Rp1p1, &sBu, &hUcached);
  ge_p1p1_to_p3(&Ru, &Rp1p1);


  // Check h == SHA512(label(4) || A || U || R || Ru || M)
  m[0] = 0xFB;
  for (count = 1; count < 32; count++)
    m[count] = 0xFF;
  memmove(m+32, pk, 32);
  /* undo the negation for U */
  fe_neg(U.X, U.X);
  fe_neg(U.T, U.T);
  ge_p3_tobytes(m+64, &U);
  ge_tobytes(m+96, &R);
  ge_p3_tobytes(m+128, &Ru);
  memmove(m+160, sm+96, smlen - 96);

  crypto_hash_sha512(hcheck, m, smlen + 64);
  sc_reduce(hcheck);

  if (crypto_verify_32(hcheck, h) == 0) {
    memmove(m,m + 64,smlen - 64);
    memset(m + smlen - 64,0,64);
    *mlen = smlen - 64;
    return 0;
  }

badsig:
  *mlen = -1;
  memset(m,0,smlen);
  return -1;
}
