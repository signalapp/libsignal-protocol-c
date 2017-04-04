#include "tests.h"


int main(int argc, char* argv[])
{
  all_fast_tests(0);
  curvesigs_slow_test(0,           10000);
  xeddsa_slow_test(0,              10000);
  xeddsa_to_curvesigs_slow_test(0, 10000);
  vxeddsa_slow_test(0,             10000);
  return 0;
}
