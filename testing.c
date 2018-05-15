#define _POSIX_C_SOURCE 200112L
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define TRUE 1
#define FALSE 0


int main(int argc, char **argv){

  // initialise the relevant structures for reading in
  const char *test_cert_example = "./cert-file2.pem";

  // the bio
  BIO *certificate_bio = NULL;

  // the certificate itself
  X509 *cert = NULL;

  // the certificate name issuer
  X509_NAME *cert_issuer = NULL;
  X509_NAME *cert_subjects = NULL;
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
  time(&rawtime);

  struct tm *current;
  // memset(current,0,sizeof(current));
  current = localtime(&rawtime);


  // convert system time to ASN1_TIME
  ASN1_TIME *before_time;

  before_time = X509_get_notBefore(cert);

  // convert the asn1_time to tm time
  // ASN1_TIME_to_tm(before_time,&before);
  BIO *b = BIO_new_fp(stdout, BIO_NOCLOSE);
  ASN1_TIME_print(b,before_time);
  printf("\n");

  // here we have the time in the time_t format -- now
  // just need to convert this into an ASN1_TIME structure for comparison
  printf("CURRENT TIME: %s\n",asctime(current));


  ASN1_TIME *current_ASN1;

  // first argument to NULL -- we want ASN1_TIME_set to return an allocated block of memory
  current_ASN1 = ASN1_TIME_set(NULL, rawtime);

  int day, sec;

  if(!ASN1_TIME_diff(&day, &sec, before_time, current_ASN1)){

  }
  // if the day difference is negative, then the current day is
  // later than the cert before time then day is > 0
  printf("%d %d\n",day,sec);
  if(day > 0 && sec > 0){
    // then before time > current
    printf("CERT DATE BEFORE\n");
  }else if(day < 0 && sec < 0){
    // THEN CURRENT > BEFORE
    printf("CERT DATE AFTER\n");
  }else if(day == 0 && sec > 0){
    printf("CERT DATE BEFORE\n");
  }else if(day == 0 && sec < 0){
    printf("CERT DATE AFTER\n");
  }else{
    printf("SAME DAY\n");
  }
  printf("\n");

  ASN1_TIME *after_time;
  after_time = X509_get_notAfter(cert);
  ASN1_TIME_print(b,after_time);
  printf("\n");
  if(!ASN1_TIME_diff(&day, &sec, before_time, current_ASN1)){

  }
  // if the day difference is negative, then the current day is
  // later than the cert before time then day is > 0
  printf("%d %d\n",day,sec);
  if(day > 0 && sec > 0){
    // then before time > current
    printf("CERT DATE BEFORE\n");
  }else if(day < 0 && sec < 0){
    // THEN CURRENT > BEFORE
    printf("CERT DATE AFTER\n");
  }else if(day == 0 && sec > 0){
    printf("CERT DATE BEFORE\n");
  }else if(day == 0 && sec < 0){
    printf("CERT DATE AFTER\n");
  }else{
    printf("SAME DAY\n");
  }


  // get the domain name in the common name

  cert_issuer = X509_get_issuer_name(cert);
  char issuer_cn[256] = "Issuer CN NOT FOUND";
  X509_NAME_get_text_by_NID(cert_issuer, NID_commonName, issuer_cn, 256);
  printf("Issuer CommonName:%s\n", issuer_cn);

  cert_subjects = X509_get_subject_name(cert);
  char subject_cn[256] = "Issuer CN NOT FOUND";
  X509_NAME_get_text_by_NID(cert_subjects, NID_commonName, subject_cn, 256);
  printf("Subject CommonName:%s\n", subject_cn);


  // convert the time values to time structs that we can use


  // get the X509_PUBKEY
  X509_PUBKEY *key;

  key = X509_get_X509_PUBKEY(cert);

  // get the public key from key

  EVP_PKEY *pubkey;
  pubkey = X509_PUBKEY_get(key);

  RSA *ppk;
  ppk = EVP_PKEY_get1_RSA(pubkey);

  //get the length

  int length = RSA_size(ppk);

  printf("%d\n",length);


  // read in the extensions

  X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));
  ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);

  char buff[1024];
  OBJ_obj2txt(buff, 1024, obj, 0);
  printf("CA: %s -- \n", buff);

  BUF_MEM *bptr = NULL;
  char *buf = NULL;

  BIO *bio = BIO_new(BIO_s_mem());
  if (!X509V3_EXT_print(bio, ex, 0, 0))
  {
      fprintf(stderr, "Error in reading extensions");
  }
  printf("GOT HERE\n");
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bptr);
  //bptr->data is not NULL terminated - add null character
  buf = (char *)malloc((bptr->length + 1) * sizeof(char));
  memcpy(buf, bptr->data, bptr->length);
  buf[bptr->length] = '\0';
  printf("GOT HERE\n");
  //Can print or parse value
  printf("--%s--\n", buf);

  // compare the certificate basic constraint with TLS Web Server Authentication
  if(strstr(buf, "TLS Web Server Authentication") != NULL){
      free(buf);
      printf("USAGE IS GOOD\n");
  }else{
      free(buf);
      printf("USAGE IS NOT GOOD\n");
  }

  // read in the extensions

  ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_subject_alt_name, -1));
  obj = X509_EXTENSION_get_object(ex);

  OBJ_obj2txt(buff, 1024, obj, 0);
  printf("CA: %s -- \n", buff);


  bio = BIO_new(BIO_s_mem());
  if (!X509V3_EXT_print(bio, ex, 0, 0))
  {
      fprintf(stderr, "Error in reading extensions");
  }
  printf("GOT HERE\n");
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bptr);
  //bptr->data is not NULL terminated - add null character
  buf = (char *)malloc((bptr->length + 1) * sizeof(char));
  memcpy(buf, bptr->data, bptr->length);
  buf[bptr->length] = '\0';
  printf("GOT HERE\n");
  //Can print or parse value
  printf("--%s--\n", buf);

  // compare the certificate basic constraint with TLS Web Server Authentication
  if(strstr(buf, "TLS Web Server Authentication") != NULL){
      //free(buf);
      printf("USAGE IS GOOD\n");
  }else{
      //free(buf);
      printf("USAGE IS NOT GOOD\n");
  }

  int token_index = 0;
  char separator[3] = ", ";
  char *token_SAN;
  char *save_SAN;
  int result;
  char url[256] = "www.google.com";
  token_SAN = strtok_r(buf,separator, &save_SAN);
  // iterate through all the DNS in the SAN

  // now set the equivalent flag to FALSE -- if we come across a domain
  // name that is equivalent, then we can change the flag to TRUE
  // we just need to return the flag
  int equivalent = FALSE;

  while(token_SAN!= NULL){
      // reset the buffer
      memset(buff,0,256);
      // copy in the token into the buffer
      strcpy(buff,token_SAN);

      // now the first 4 characters are always DNS:
      // therefore we can skip over these 4
      char *san = buff+strlen("DNS:");

      // now *san should point to the portion of the buffer that contains the DNS path

      // the DNS path can be in the form www.*, *.example.com, example.com
      // first try a strcmp

      if(strcmp(san,url) == 0){
          // then it is an exact match -- hence we can return true
          equivalent = TRUE;
      }
      token_SAN = strtok_r(NULL,separator, &save_SAN);
      printf("DNS: %s\n",san);
  }
  printf("%s is %d\n",url,equivalent);

  X509_free(cert);
  BIO_free_all(certificate_bio);
  // BIO_free_all(bio);
  return 0;
}
