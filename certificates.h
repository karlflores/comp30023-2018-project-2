#include "checkers.h"
#include "helpers.h"

#define SUCCESS 1
#define FAILURE -1

/**
* Verify the certificate specificed by cert_path with url.
*
* @param: cert_path -- path to the certificate
* @param: url -- the url to test against
* @return: 1 - TRUE , 0 - FALSE
*/
int verify_certificate(const char *cert_path, const char *url);

/**
* Process the csv files of certificates and URL
*
* @param: input_path -- path to the input file
* @return: 1 - SUCCESS, 0 - FAILURE
*/
int process_certificate_input(const char *input_path);
