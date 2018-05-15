#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define LATER_TIME 1
#define SAME_TIME 0
#define EARLIER_TIME -1
#define BUFFSZ 256
#define TRUE 1
#define FALSE 0
#define BYTE_TO_BITS 8
#define MIN_PUBKEY_LENGTH 2048

int check_not_after(X509 *cert);

int check_not_before(X509 *cert);

int compare_ASN1_TIMES(ASN1_TIME *from, ASN1_TIME *to);

int check_common_name(X509 *cert, const char *url);

int check_pubkey_length(X509 *cert);

int check_pubkey_ext(X509 *cert);
