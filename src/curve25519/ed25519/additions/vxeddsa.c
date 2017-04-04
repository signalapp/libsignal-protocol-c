#include <string.h>
#include "ge.h"
#include "crypto_additions.h"
#include "zeroize.h"
#include "vxeddsa.h"
#include "crypto_verify_32.h"

int vxed25519_sign(unsigned char* signature_out,
                   const unsigned char* curve25519_privkey,
                   const unsigned char* msg, const unsigned long msg_len,
                   const unsigned char* random)
{
  unsigned char a[32], aneg[32];
  unsigned char A[32];
  ge_p3 Bv, ed_pubkey_point;
  unsigned char sigbuf[MAX_MSG_LEN + 160]; /* working buffer */
  unsigned char sign_bit = 0;

  if (msg_len > MAX_MSG_LEN) {
    memset(signature_out, 0, 96);
    return -1;
  }
  /* Convert the Curve25519 privkey to an Ed25519 public key */
  ge_scalarmult_base(&ed_pubkey_point, curve25519_privkey);
  ge_p3_tobytes(A, &ed_pubkey_point);

  /* Force Edwards sign bit to zero */
  sign_bit = (A[31] & 0x80) >> 7;
  memcpy(a, curve25519_privkey, 32);
  sc_neg(aneg, a);
  sc_cmov(a, aneg, sign_bit); 
  A[31] &= 0x7F;
  
  calculate_Bv_and_V(&Bv, signature_out, sigbuf, a, A, msg, msg_len);

  /* Perform an Ed25519 signature with explicit private key */
  crypto_vsign_modified(sigbuf, msg, msg_len, a, A, random, &Bv, signature_out /*V*/);
  memmove(signature_out+32, sigbuf, 64);

  zeroize(a, 32);
  zeroize(aneg, 32);
  return 0;
}

int vxed25519_verify(unsigned char* vrf_out,
                     const unsigned char* signature,
                     const unsigned char* curve25519_pubkey,
                     const unsigned char* msg, const unsigned long msg_len)
{
  fe u; 
  fe y;
  unsigned char ed_pubkey[32];
  unsigned char verifybuf[MAX_MSG_LEN + 160]; /* working buffer */
  unsigned char verifybuf2[MAX_MSG_LEN + 160]; /* working buffer #2 ?? !!! */
  ge_p3 Bv;

  if (msg_len > MAX_MSG_LEN) {
    return -1;
  }

  /* Convert the Curve25519 public key (u) into an Ed25519 public key.  

     y = (u - 1) / (u + 1)

     NOTE: u=-1 is converted to y=0 since fe_invert is mod-exp
  */
  if (!fe_isreduced(curve25519_pubkey))
      return -1;
  fe_frombytes(u, curve25519_pubkey);
  fe_montx_to_edy(y, u);
  fe_tobytes(ed_pubkey, y);

  calculate_Bv(&Bv, verifybuf, ed_pubkey, msg, msg_len);

  memmove(verifybuf, signature, 96);
  memmove(verifybuf+96, msg, msg_len);

  /* Then perform a signature verification, return 0 on success */
  /* The below call has a strange API: */
  /* verifybuf = V || h || s || message */
  /* verifybuf2 = used as buffer, gets the VRF output if success */
  if (crypto_vsign_open_modified(verifybuf2, verifybuf, 96 + msg_len, ed_pubkey, &Bv) == 0) {
    memmove(vrf_out, verifybuf2, 32);
    return 0;
  } else {
    memset(vrf_out, 0, 32);
    return -1;
  }
}
