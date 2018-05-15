#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TRUE 1
#define FALSE 0
#define BUFFSZ 256

/*
* HELPER FUNCTIONS TO COMPARE WILDCARD URLS
*/

// compare a wildcard url with a test-url to see if they are equivalent
int comp_wildcard(const char *wildcard, const char *url);

// tests if a url is a valid wildcard
int is_wildcard(const char *url);

// counts the number of periods in a given url -- this should be the same in two URLS that are assumes to be equivalent
int count_period(const char *url);

/*
* HELPER METHODS FOR PROCESSING AND COMPARING THE ACTUAL WILDCARD ENTRY
*/

// compares the characters before the asterisk
int compare_before_wc(char *token_wc,char *token_url);

// compares the characters after the asterisk
int compare_after_wc(char *token_wc,char *token_url);
