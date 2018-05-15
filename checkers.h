#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define LATER_TIME 1
#define SAME_TIME 0
#define EARLIER_TIME -1
#define BUFFSZ 256
#define TRUE 1
#define FALSE 0

int checkNotAfter(X509 *cert);

int checkNotBefore(X509 *cert);

int compare_ASN1_TIMES(ASN1_TIME *from, ASN1_TIME *to);

int checkCommonName(X509 *cert, const char *url);
