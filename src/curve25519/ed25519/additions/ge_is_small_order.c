#include "crypto_additions.h"
#include "ge.h"
#include "utility.h"
#include "stdio.h"

/*
return 1 if f == g
return 0 if f != g
*/

int ge_is_small_order(const ge_p3 *p)
{
  ge_p1p1 p1p1;
  ge_p2 p2;
  fe zero;

  ge_p3_dbl(&p1p1, p);
  ge_p1p1_to_p2(&p2, &p1p1);

  ge_p2_dbl(&p1p1, &p2);
  ge_p1p1_to_p2(&p2, &p1p1);

  ge_p2_dbl(&p1p1, &p2);
  ge_p1p1_to_p2(&p2, &p1p1);

  fe_0(zero);

  /* Check if 8*p == neutral element == (0, 1) */
  return (fe_isequal(p2.X, zero) & fe_isequal(p2.Y, p2.Z));
}
