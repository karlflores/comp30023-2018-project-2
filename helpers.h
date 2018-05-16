#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/asn1.h>

#define LATER_TIME 1
#define SAME_TIME 0
#define EARLIER_TIME -1

/**
* Reconstruct the full path to a file based on its relative location and the
* base path
*
* @param base_path: base path string
* @param relative_path: relative path string
* @return : full path string in allocated memory that will need to be freed
*           after use
*/
char *reconstruct_full_path(const char *base_path, const char *relative_path);

/**
* Compares two times in ASN1 format. This compares the 'to' time from the
* 'from' time
*
* @param from: This is the time we are comparing against in ASN1 format
* @param to: This is the time we want to compare in ASN1 format
*/
int compare_ASN1_TIMES(ASN1_TIME *from, ASN1_TIME *to);

/**
* Counts the number of periods in a given url
*
* @param url: the url to count
* @param : number of periods in the url
*/
int count_period(const char *url);
