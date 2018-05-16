#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "helpers.h"

#define TRUE 1
#define FALSE 0
#define BUFFSZ 256

/*
* HELPER FUNCTIONS TO COMPARE WILDCARD URLS
*/

/**
* Compare a wildcard url with a test-url to see if they are equivalent
*
* @param wildcard: the wildcard url
* @param url: the url to test
* @return : 1 - TRUE , 0 - FALSE
*/
int comp_wildcard(const char *wildcard, const char *url);

/**
* Test if a url is a wildcard or not
*
* @param url: the url to test
* @return : 1 - TRUE , 0 - FALSE
*/
int is_wildcard(const char *url);

/*
* HELPER METHODS FOR PROCESSING AND COMPARING THE ACTUAL WILDCARD ENTRY
*/

/**
* Compare the characters before the asterisk in the wildcard url segment
*
* @param token_wc: the wildcard url segment containing the asterisk
* @param token_url: the segment in the url that is in the same position as
*                   the asterisk in the wildcard url
* @return : 1 - TRUE , 0 - FALSE
*/
int compare_before_wc(char *token_wc,char *token_url);

/**
* Compare the characters after the asterisk in the wildcard url segment
*
* @param token_wc: the wildcard url segment containing the asterisk
* @param token_url: the segment in the url that is in the same position as
*                   the asterisk in the wildcard url
* @return : 1 - TRUE , 0 - FALSE
*/
int compare_after_wc(char *token_wc,char *token_url);
