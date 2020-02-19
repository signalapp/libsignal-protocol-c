#include "ge.h"

void ge_p3_tobytes(unsigned char *s,const ge_p3 *h)
{
  fe recip;
  fe x;
  fe y;

  fe_invert(recip,h->Z);
  fe_mul(x,h->X,recip);
  fe_mul(y,h->Y,recip);
  fe_tobytes(s,y);
  s[31] ^= fe_isnegative(x) << 7;
}

void ge_p3_tobytes_128(unsigned char *s, const ge_p3 *h) {
  fe_tobytes(&s[0], h->X);
  fe_tobytes(&s[32], h->Y);
  fe_tobytes(&s[64], h->Z);
  fe_tobytes(&s[96], h->T);
}
