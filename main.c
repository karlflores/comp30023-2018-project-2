#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>


int main(int argc, char **argv){

  // initialise the relevant structures for reading in
  const char *test_cert_example = "./cert-file2.pem";

  // the bio
  BIO *certificate_bio = NULL;

  // the certificate itself
  X509 *cert = NULL;

  // the certificate name issuer
  X509_NAME *cert_issuer = NULL;

  //X509_CINF *cert
  X509_CINF *cert_inf = NULL;

  // collections of objects -- this is a stack
  STACK_OF(X509_EXTENSION) *ext_list;

  // initialise OpenSSL
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();


  // read in the certificate first

  certificate_bio = BIO_new(BIO_s_file());

  // read the actual certificate
  if(BIO_read_filename(certificate_bio, test_cert_example) == 0){
    fprintf(stderr, "ERROR: can't read in BIO filename\n");
    exit(EXIT_FAILURE);

  }

  cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL);
  if(cert == 0){
    fprintf(stderr, "ERROR: can't load cert\n");
    exit(EXIT_FAILURE);
  }

  // access the certificate values

  // access the time values:
  struct tm before;
  memset(&before,0,sizeof(before));
  time_t rawtime;
  struct tm *current = localtime(&rawtime);
  memset(current,0,sizeof(struct tm));

  // convert system time to ASN1_TIME
  ASN1_TIME *before_time;
  before_time = X509_get0_notBefore(cert);

  // convert the asn1_time to tm time
  ASN1_TIME_to_tm(before_time,&before);
  printf("ASN1 CERT TIME: %s\n",asctime(&before));
  printf("CURRENT TIME: %s\n",asctime(current));


  ASN1_TIME *after_time;
  after_time = X509_get0_notAfter(cert);

  // convert the time values to time structs that we can use

  X509_free(cert);
  BIO_free_all(certificate_bio);
  // BIO_free_all(bio);
  return 0;
}
