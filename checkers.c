#include "checkers.h"

int check_not_after(X509 *cert){
    // BIO *b = BIO_new_fp(stdout, BIO_NOCLOSE);
    // access the the current system time values:
    time_t rawtime;
    // get the current time
    time(&rawtime);

    // convert notBefore field time to ASN1_TIME structure
    ASN1_TIME *not_after_time;

    not_after_time = X509_get_notAfter(cert);
    // printf("NOT AFTER TIME \n");
    // ASN1_TIME_print(b,not_after_time);
    // printf("\n");
    // error checking
    if(not_after_time == NULL){
        fprintf(stderr,"ERROR: Can't access Not After Time Field\n");
        exit(EXIT_FAILURE);
    }

    // convert time_t (system time) into ASN1_TIME format for comparison
    ASN1_TIME *system_time;

    // first argument to NULL -- we want ASN1_TIME_set to return an allocated block of memory
    system_time = ASN1_TIME_set(NULL, rawtime);
    // ASN1_TIME_print(b,system_time);
    // printf("\n");
    // compare the system time and the after time
    // return 1 -- if
    int comp = compare_ASN1_TIMES(not_after_time, system_time);
    // printf("COMPARE: %d\n",comp);
    // free the resources that have been allocated
    free(system_time);

    // if the system time is later than the after time -- this is
    // not what we want, therefore return 0
    // if the system time is earlier than the after time (or is equal??)
    // therefore return 1
    if(comp == EARLIER_TIME){
        return TRUE;
    }else{
        return FALSE;
    }
}

int check_not_before(X509 *cert){
    // BIO *b = BIO_new_fp(stdout, BIO_NOCLOSE);
    // access the the current system time values:
    time_t rawtime;
    // get the current time
    time(&rawtime);

    // convert notBefore field time to ASN1_TIME structure
    ASN1_TIME *not_before_time;
    not_before_time = X509_get_notBefore(cert);
    // printf("\nNOT BEFORE TIME \n");
    // ASN1_TIME_print(b,not_before_time);
    // printf("\n");
    // error checking
    if(not_before_time == NULL){
        fprintf(stderr,"ERROR: Can't access Not Before Time Field\n");
        exit(EXIT_FAILURE);
    }

    // convert time_t (system time) into ASN1_TIME format for comparison
    ASN1_TIME *system_time;

    // first argument to NULL -- we want ASN1_TIME_set to return an allocated block of memory

    system_time = ASN1_TIME_set(NULL, rawtime);
    // ASN1_TIME_print(b,system_time);
    // printf("\n");
    // compare the system time and the before time
    // return 1 -- if
    int comp = compare_ASN1_TIMES(not_before_time, system_time);
    // printf("COMPARE: %d\n",comp);
    // free the resources that have been allocated
    free(system_time);

    // if the system time is later than the before time -- this is
    // what we want, therefore return 1
    // if the system time is earlier than the before time (or is equal??)
    // therefore return 0
    if(comp == EARLIER_TIME){
        return FALSE;
    }else{
        return TRUE;
    }
}

// CHECK COMMON NAME
int check_common_name(X509 *cert, const char *url){
    // check the common name with supplied url
    char subject_cn[BUFFSZ] = "Subject CN NOT FOUND";
    // retrieve the common name from the certificate
    X509_NAME *cert_subjects;
    cert_subjects = X509_get_subject_name(cert);

    if(cert_subjects == NULL){
        fprintf(stderr, "ERROR: Can't Gen Subject Fields\n");
        return FALSE;
    }

    // retrieve the common name
    X509_NAME_get_text_by_NID(cert_subjects, NID_commonName, subject_cn, BUFFSZ);
    // printf("COMMON NAME: %s\n",subject_cn);
    // need to test whether the subject name matches the testing url.

    // first try a strcmp
    int authenticated = FALSE;

    if(strcmp(subject_cn,url) == 0){
        // then it is an exact match -- hence we can return true
        return TRUE;
    }else{
        // need to check whether the CN is a wildcard

        if(is_wildcard(subject_cn)){
            // the subject cn is a wild card

            // return the comparison value between the subject_CN and the tested URL
            authenticated = comp_wildcard(subject_cn,url);
            if(authenticated == FALSE){
                authenticated = check_SAN(cert,url);
            }

        }else{
            // if it is not a wild card -- then the CN does not match
            // we then need to check the SAN
            //return FALSE;
            authenticated = check_SAN(cert,url);
        }
    }

    return authenticated;
}

// check the minimum pubkey length
int check_pubkey_length(X509 *cert){
    // get the Subject Pubkey info -- X509_PUBKEY structure
    X509_PUBKEY *key;
    key = X509_get_X509_PUBKEY(cert);

    // get the public key from key -- convert to EVP_PKEY strcture so that we can extract the RSA key from it
    EVP_PKEY *pubkey;
    pubkey = X509_PUBKEY_get(key);

    // extract the RSA public key
    RSA *ppk;
    ppk = EVP_PKEY_get1_RSA(pubkey);

    //get the length of the key in bits
    int length = RSA_size(ppk)*BYTE_TO_BITS;

    return length >= MIN_PUBKEY_LENGTH;
}

// validate the the pubkey extensions
int check_basic_constraints(X509 *cert){
    // read in the extensions
    // get the location of the basic constrains extensions
    int bc_loc = X509_get_ext_by_NID(cert, NID_basic_constraints, -1);
    if(bc_loc < 0){
        fprintf(stderr,"ERROR: Can't locate Basic Constraints in Certificate\n");
        return FALSE;
    }
    // get the string representing this extension
    char *bc = get_extension_str(cert,bc_loc);
    // printf("THIS CERT BC: %s\n",bc);


    if(bc == NULL){
        fprintf(stderr,"ERROR: Can't locate Basic Constraints in Certificate\n");
        return FALSE;
    }

    // compare the certificate basic constraint with CA:FALSE
    if(strcmp(bc,"CA:FALSE") == 0){
        free(bc);
        return TRUE;
    }else{
        free(bc);
        return FALSE;
    }

}

// che
int check_ext_key_usage(X509 *cert){
    // read in the extensions
    // get the location of the basic constrains extensions
    int ku_loc = X509_get_ext_by_NID(cert, NID_ext_key_usage, -1);
    if(ku_loc < 0){
        fprintf(stderr,"ERROR: Can't locate Basic Constraints in Certificate\n");
        return FALSE;
    }
    // get the string representing this extension
    char *ku = get_extension_str(cert,ku_loc);
    if(ku == NULL){
        fprintf(stderr,"ERROR: Can't locate Basic Constraints in Certificate\n");
        return FALSE;
    }
    // compare the certificate basic constraint with TLS Web Server Authentication
    if(strstr(ku, "TLS Web Server Authentication") != NULL){
        free(ku);
        return TRUE;
    }else{
        free(ku);
        return FALSE;
    }
}

// returns allocated memory containing a string of the relevant extension field
char *get_extension_str(X509 *cert, int location){

    X509_EXTENSION *extension = X509_get_ext(cert, location);

    //assert extension
    if(extension == NULL){
        fprintf(stderr,"ERROR: Can't locate Key Extension in Certificate\n");
        return NULL;
    }

    // get the Basic Constraint value

    BUF_MEM *bc_ptr = NULL;
    char *bc = NULL;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, extension, 0, 0)){
        fprintf(stderr, "ERROR: Unable to read in Key Extension\n");
        return NULL;
    }

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bc_ptr);

    // allocate memory for the buffer
    bc = (char *)malloc((bc_ptr->length + 1) * sizeof(char));
    if(bc == NULL){
        fprintf(stderr,"ERROR: Could not allocate memory for Basic Constraints\n");
        return NULL;
    }
    // copy the string and add the null character to the end
    memcpy(bc, bc_ptr->data, bc_ptr->length);
    bc[bc_ptr->length] = '\0';

    // return the final value
    // printf("EXTENSIONS: %s \n",bc);
    return bc;

}

// This function checks the url with the subject alternative names in the certificate -- it iterates through all of them, checking for equivalence. It also is able to handle wildcards to the RFC4985 standard
int check_SAN(X509 *cert, const char *url){
    // read in the extensions
    // get the location of the subject alternative names
    int SAN_loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if(SAN_loc < 0){
        fprintf(stderr,"ERROR: Can't locate Subject Alternative Name in Certificate\n");
        return FALSE;
    }
    // get the string representing this extension
    char *SAN = get_extension_str(cert,SAN_loc);
    if(SAN == NULL){
        fprintf(stderr,"ERROR: Can't load Subject Alternative Name as string\n");
        return FALSE;
    }
    // now we need to tokenise the subject alternative name
    // get the first token of both the url and the wildcard
    char separator[3] = ", ";
    char *token_SAN;
    char *save_SAN;

    token_SAN = strtok_r(SAN,separator, &save_SAN);
    char buff[BUFFSZ];
    // iterate through all the DNS in the SAN

    // now set the equivalent flag to FALSE -- if we come across a domain
    // name that is equivalent, then we can change the flag to TRUE
    // we just need to return the flag
    int equivalent = FALSE;

    while(token_SAN!= NULL){
        // reset the buffer
        memset(buff,0,BUFFSZ);
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
        }else{
            // need to check whether the san is a wildcard
            if(is_wildcard(san)){
                // see if the san (wildcard) is equivalent to the test url
                if(comp_wildcard(san,url)){
                    equivalent = TRUE;

                    // no use to checking the rest of the list -- therefore we can break out of the loop once we find a match
                    break;
                }

            }
        }
        token_SAN = strtok_r(NULL,separator, &save_SAN);
        // printf("DNS: %s\n",token_SAN);
    }

    free(SAN);
    // if we have found an equivalent DNS then the flag would have been changed
    return equivalent;
}
