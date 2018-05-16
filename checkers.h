#define _POSIX_C_SOURCE 200112L

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "wildcards.h"

#define LATER_TIME 1
#define SAME_TIME 0
#define EARLIER_TIME -1
#define BUFFSZ 256
#define MAXBUFFSZ 1024
#define TRUE 1
#define FALSE 0
#define ERROR -1
#define BYTE_TO_BITS 8
#define MIN_PUBKEY_LENGTH 2048

/*
* FUNCTIONS TO CHECK THE RELEVANT FILEDS OF A GIVEN CERTIFICATE
*
* THESE FUNCTIONS DO NOT CHECK IF THE CERTIFICATE IS VALID -- IT IS ASSUMED THAT THE CERTIFICATE IS VALID
*
*/

int check_not_after(X509 *cert);

int check_not_before(X509 *cert);

int compare_ASN1_TIMES(ASN1_TIME *from, ASN1_TIME *to);

int check_common_name(X509 *cert, const char *url);

int check_pubkey_length(X509 *cert);

int check_basic_constraints(X509 *cert);

int check_ext_key_usage(X509 *cert);

char *get_extension_str(X509 *cert, int location);

int check_SAN(X509 *cert, const char *url);
