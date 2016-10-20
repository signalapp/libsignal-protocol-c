#include <string.h>
#include "crypto_sign.h"
#include "crypto_hash_sha512.h"
#include "ge.h"
#include "sc.h"
#include "zeroize.h"
#include "crypto_additions.h"

/* NEW: Compare to pristine crypto_sign() 
   Uses explicit private key for nonce derivation and as scalar,
   instead of deriving both from a master key.
*/
int crypto_vsign_modified(
  unsigned char *sm,
  const unsigned char *M,unsigned long Mlen,
  const unsigned char *a, 
  const unsigned char *A,
  const unsigned char *random,
  const ge_p3 *Bv,
  const unsigned char *V
)
{
  unsigned char r[64];
  unsigned char h[64];
  ge_p3 R, Rv;
  int count=0;

  /* r = SHA512(label(3) || a || V || random(64)) */
  sm[0] = 0xFC;
  for (count = 1; count < 32; count++)
    sm[count] = 0xFF;

  memmove(sm + 32, a, 32); /* Use privkey directly for nonce derivation */
  memmove(sm + 64, V, 32);

  memmove(sm + 96, random, 64); /* Add suffix of random data */
  crypto_hash_sha512(r, sm, 160);

  sc_reduce(r);
  ge_scalarmult_base(&R, r);
  ge_scalarmult(&Rv, r, Bv);

  /* h = SHA512(label(4) || A || V || R || Rv || M) */
  sm[0] = 0xFB;
  memmove(sm + 32, A, 32);
  memmove(sm + 64, V, 32);
  ge_p3_tobytes(sm+96, &R);
  ge_p3_tobytes(sm+128, &Rv);
  memmove(sm + 160, M, Mlen);

  crypto_hash_sha512(h, sm, Mlen + 160);
  sc_reduce(h);

  memmove(sm, h, 32);               /* Write h */
  sc_muladd(sm + 32, h, a, r);      /* Write s */

  /* Erase any traces of private scalar or
     nonce left in the stack from sc_muladd. */
  zeroize_stack();
  zeroize(r, 64);
  return 0;
}
