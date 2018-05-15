#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TRUE 1
#define FALSE 0
#define BUFFSZ 256

int comp_wildcard(const char *wildcard, const char *url);

int is_wildcard(const char *url);

// if *.example.com -- index == 0
// if foo.*.example.com -- index == 1

int get_wildcard_index(const char *wildcard);

int count_period(const char *url);

int compare_before_wc(char *token_wc,char *token_url);

int compare_after_wc(char *token_wc,char *token_url);
