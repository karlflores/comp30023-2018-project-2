#include "checkers.h"

int check_not_after(X509 *cert){
    time_t sys_time_h;
    // get the current time
    time(&sys_time_h);

    // convert notBefore field time to ASN1_TIME structure
    ASN1_TIME *not_after_time;

    not_after_time = X509_get_notAfter(cert);

    // error checking
    if(not_after_time == NULL){
        fprintf(stderr,"ERROR: Can't access Not After Time Field\n");
        return ERROR;
    }

    // convert time_t (system time) into ASN1_TIME format for comparison
    ASN1_TIME *system_time;

    // first argument to NULL -- we want ASN1_TIME_set to return an allocated block of memory
    system_time = ASN1_TIME_set(NULL, sys_time_h);

    // compare the system time and the after time
    int comp = compare_ASN1_TIMES(not_after_time, system_time);

    // free the resources that have been allocated
    ASN1_STRING_free(system_time);

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

    // access the the current system time values:
    time_t sys_time_h;

    // get the current time
    time(&sys_time_h);

    // convert notBefore field time to ASN1_TIME structure
    ASN1_TIME *not_before_time;
    not_before_time = X509_get_notBefore(cert);

    // error checking
    if(not_before_time == NULL){
        fprintf(stderr,"ERROR: Can't access Not Before Time Field\n");
        return ERROR;
    }

    // convert time_t (system time) into ASN1_TIME format for comparison
    ASN1_TIME *system_time;

    // first argument to NULL -- we want ASN1_TIME_set to return an allocated block of memory

    // conver time_h to ASN1 encoding
    system_time = ASN1_TIME_set(NULL, sys_time_h);

    // compare the system time and the before time
    int comp = compare_ASN1_TIMES(not_before_time, system_time);

    // free the resources that have been allocated
    ASN1_STRING_free(system_time);
    // free(system_time);

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
        return ERROR;
    }

    // retrieve the common name using NID
    X509_NAME_get_text_by_NID(cert_subjects, NID_commonName, subject_cn, BUFFSZ);

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

            // if the CN is a wildcard, but the comparison returns false, we
            // need to check if it is equivalent to a SAN that is listed
            if(authenticated == FALSE){
                authenticated = check_SAN(cert,url);
            }

        }else{
            // if it is not a wild card -- then the CN does not match
            // we then need to check the SAN
            authenticated = check_SAN(cert,url);
        }
    }

    // return if the url has been authenticated via CN/SAN
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

    // free the relavent structures
    EVP_PKEY_free(pubkey);
    RSA_free(ppk);
    return length >= MIN_PUBKEY_LENGTH;
}

// validate the the pubkey extensions
int check_basic_constraints(X509 *cert){
    // read in the extensions
    // get the location of the basic constrains extensions
    int bc_loc = X509_get_ext_by_NID(cert, NID_basic_constraints, -1);
    if(bc_loc < 0){
        fprintf(stderr,"ERROR: Can't locate Basic Constraints in Certificate\n");
        return ERROR;
    }
    // get the string representing this extension
    char *bc = get_extension_str(cert,bc_loc);
    if(bc == NULL){
        fprintf(stderr,"ERROR: Can't locate Basic Constraints in Certificate\n");
        return ERROR;
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
        return ERROR;
    }
    // get the string representing this extension
    char *ku = get_extension_str(cert,ku_loc);
    if(ku == NULL){
        fprintf(stderr,"ERROR: Can't allocate memory for Ext. Key Usage\n");
        return ERROR;
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

    // get the extension string
    BUF_MEM *ex_ptr = NULL;
    char *ex = NULL;

    BIO *bio = BIO_new(BIO_s_mem());

    if (!X509V3_EXT_print(bio, extension, 0, 0)){
        fprintf(stderr, "ERROR: Unable to read in Key Extension\n");
        // free the bio
        if(!BIO_free(bio)){
            fprintf(stderr,"ERROR: Could not free bio.\n");
            return NULL;
        }
        return NULL;
    }

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &ex_ptr);

    // allocate memory for the buffer
    ex = (char *)malloc((ex_ptr->length + 1) * sizeof(char));

    // assert the buffer
    if(ex == NULL){
        fprintf(stderr,"ERROR: Could not allocate memory for Basic Constraints\n");
        // free the bio if it comes to it
        if(!BIO_free(bio)){
            fprintf(stderr,"ERROR: Could not free bio.\n");
            return NULL;
        }

        return NULL;
    }

    // copy the string and add the null character to the end
    memcpy(ex, ex_ptr->data, ex_ptr->length);
    ex[ex_ptr->length] = '\0';

    // return the final value
    if(!BIO_free(bio)){
        fprintf(stderr,"ERROR: Could not free bio.\n");
    }

    // return the allocated memory
    return ex;

}

// This function checks the url with the subject alternative names in the certificate -- it iterates through all of them, checking for equivalence. It also is able to handle wildcards to the RFC4985 standard
int check_SAN(X509 *cert, const char *url){
    // read in the extensions
    // get the location of the subject alternative names
    int SAN_loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if(SAN_loc < 0){
        fprintf(stderr,"ERROR: Can't locate Subject Alternative Name in Certificate\n");
        return ERROR;
    }
    // get the string representing this extension
    char *SAN = get_extension_str(cert,SAN_loc);
    if(SAN == NULL){
        fprintf(stderr,"ERROR: Can't load Subject Alternative Name as string\n");
        return ERROR;
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
        // therefore we can skip over these 4 -- adjust to point to memory
        // location 4 bytes along
        char *san = buff+strlen("DNS:");

        // now *san should point to the portion of the buffer that contains the DNS path

        // the DNS path can be in the form www.*, *.example.com, example.com

        // first try a strcmp between the SAN and the url
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
        // get the next token in the url
        token_SAN = strtok_r(NULL,separator, &save_SAN);
    }
    // free the allocated memory for SAN
    free(SAN);

    // if we have found an equivalent DNS then the flag would have been changed
    return equivalent;
}
