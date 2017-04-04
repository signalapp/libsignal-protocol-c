#ifndef __TESTS_H__
#define __TESTS_H__

/* silent = 0 : prints info+error messages to stdout, abort() on test failure
 * silent = 1 : returns 0 for success, anything else for failure 
 * iterations : hardcoded known-good values are at 10000, so run at least this many
 */

int sha512_fast_test(int silent);
int strict_fast_test(int silent);
int elligator_fast_test(int silent);
int curvesigs_fast_test(int silent);
int xeddsa_fast_test(int silent);
int vxeddsa_fast_test(int silent);

int curvesigs_slow_test(int silent, int iterations);
int xeddsa_slow_test(int silent, int iterations);
int xeddsa_to_curvesigs_slow_test(int silent, int iterations);
int vxeddsa_slow_test(int silent, int iterations);

int all_fast_tests(int silent);

#endif
