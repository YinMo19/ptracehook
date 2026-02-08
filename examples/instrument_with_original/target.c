#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int calc(int a, int b) {
  return a + b;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <a> <b>\n", argv[0]);
    return 1;
  }

  int a = atoi(argv[1]);
  int b = atoi(argv[2]);
  int r = calc(a, b);
  printf("calc(%d, %d) = %d\n", a, b, r);
  return 0;
}
