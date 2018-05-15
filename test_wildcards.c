#include "wildcards.h"

int main(int argc, char **argv){
  const char wildcard_1[] = "*.example.com";
  const char wildcard_2[] = "example.com";
  const char wildcard_3[] = "f*.example.com";
  const char wildcard_4[] = "*f.bar.example.com";

  const char url_test_1[] = "www.example.com";
  const char url_test_2[] = "foobzz.example.com";
  if(is_wildcard(wildcard_1) == TRUE){
    printf("WILDCARD 1 IS A WILDCARD\n");
  }
  if(is_wildcard(wildcard_2) == TRUE){
    printf("WILDCARD 2 IS A WILDCARD\n");
  }
  if(is_wildcard(wildcard_3) == TRUE){
    printf("WILDCARD 3 IS A WILDCARD\n");
  }
  if(is_wildcard(wildcard_4) == TRUE){
    printf("WILDCARD 4 IS A WILDCARD\n");
  }

  if(comp_wildcard(wildcard_1, url_test_1) == TRUE){
    printf("1 TRUE\n");
  }

  if(comp_wildcard(wildcard_3, url_test_2) == TRUE){
    printf("2 TRUE\n");
  }
  return 0;
}
