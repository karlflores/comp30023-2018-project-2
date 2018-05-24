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
#include "helpers.h"

#define BUFFSZ 256
#define MAXBUFFSZ 1024
#define TRUE 1
#define FALSE 0
#define ERROR -1
#define BYTE_TO_BITS 8
#define MIN_PUBKEY_LENGTH 2048
#define NOT_FOUND -2

/*
* FUNCTIONS TO CHECK THE RELEVANT FILEDS OF A GIVEN CERTIFICATE
*
* THESE FUNCTIONS DO NOT CHECK IF THE CERTIFICATE IS VALID -- IT IS ASSUMED THAT THE CERTIFICATE IS VALID
*
*/

/**
* Check the not before date field
*
* @param cert: X509 Certificate object to verify
* @return: 1 - TRUE, 0 - FALSE
*/
int check_not_after(X509 *cert);

/**
* Check the not after date  field
*
* @param cert: X509 Certificate object to verify
* @return: 1 - TRUE, 0 - FALSE
*/
int check_not_before(X509 *cert);

/**
* Check the common name against the specified url
*
* @param cert: X509 Certificate object to verify
* @param url: URL to test the certificate against
* @return: 1 - TRUE, 0 - FALSE
*/
int check_common_name(X509 *cert, const char *url);

/**
* Check if the public key bit length satisfies the minimum length
*
* @param cert: X509 Certificate object to verify
* @return: 1 - TRUE, 0 - FALSE, ERROR -1, NOT_FOUND -2
*/
int check_pubkey_length(X509 *cert);

/**
* Check the basic constraints of the certificate
*
* @param cert: X509 Certificate object to verify
* @return: 1 - TRUE, 0 - FALSE
*/
int check_basic_constraints(X509 *cert);

/**
* Check the extended key usage of the certificate
*
* @param cert: X509 Certificate object to verify
* @return: 1 - TRUE, 0 - FALSE
*/
int check_ext_key_usage(X509 *cert);

/**
* Get a string representing the extension at the required location
*
* @param cert: X509 Certificate object to verify
* @return: 1 - TRUE, 0 - FALSE
*/
char *get_extension_str(X509 *cert, int location);

/**
* Check a URL against the Subject Alternative Names in the certificate
*
* @param cert: X509 Certificate object to verify
* @param url: URL to test the certificate against
* @return: 1 - TRUE, 0 - FALSE
*/
int check_SAN(X509 *cert, const char *url);
