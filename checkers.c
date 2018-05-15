#include "checkers.h"

int check_not_after(X509 *cert){
    // access the the current system time values:
    time_t rawtime;
    // get the current time
    time(&rawtime);

    // convert notBefore field time to ASN1_TIME structure
    ASN1_TIME *not_after_time;
    not_after_time = X509_get_notAfter(cert);
    // error checking
    if(not_after_time == NULL){
        fprintf(stderr,"ERROR: Can't access Not After Time Field\n");
        exit(EXIT_FAILURE);
    }

    // convert time_t (system time) into ASN1_TIME format for comparison
    ASN1_TIME *system_time;

    // first argument to NULL -- we want ASN1_TIME_set to return an allocated block of memory
    system_time = ASN1_TIME_set(NULL, rawtime);

    // compare the system time and the after time
    // return 1 -- if
    int comp = compare_ASN1_TIMES(not_after_time,system_time);

    // free the resources that have been allocated
    free(system_time);

    // if the system time is later than the after time -- this is
    // not what we want, therefore return 0
    // if the system time is earlier than the after time (or is equal??)
    // therefore return 1
    return comp < 0;
}

int check_not_before(X509 *cert){
    // access the the current system time values:
    time_t rawtime;
    // get the current time
    time(&rawtime);

    // convert notBefore field time to ASN1_TIME structure
    ASN1_TIME *not_before_time;
    not_before_time = X509_get_notBefore(cert);
    // error checking
    if(not_before_time == NULL){
        fprintf(stderr,"ERROR: Can't access Not Before Time Field\n");
        exit(EXIT_FAILURE);
    }

    // convert time_t (system time) into ASN1_TIME format for comparison
    ASN1_TIME *system_time;

    // first argument to NULL -- we want ASN1_TIME_set to return an allocated block of memory
    system_time = ASN1_TIME_set(NULL, rawtime);

    // compare the system time and the before time
    // return 1 -- if
    int comp = compare_ASN1_TIMES(not_before_time,system_time);

    // free the resources that have been allocated
    free(system_time);

    // if the system time is later than the before time -- this is
    // what we want, therefore return 1
    // if the system time is earlier than the before time (or is equal??)
    // therefore return 0
    return comp > 0;

}

int compare_ASN1_TIMES(ASN1_TIME *from, ASN1_TIME *to){

    int comp_day, comp_sec;

    if(!ASN1_TIME_diff(&comp_day, &comp_sec, from, to)){
        fprintf("ERROR: Time\\s not in correct ASN1 time format\n");
        exit(EXIT_FAILURE);
    }

    // if we get here, we can begin to check the day and sec values
    // if the day difference is negative, then the current day is
    // later than the cert before time then day is > 0

    if(day > 0 && sec > 0){
        // then to time > from time
        printf("CERT DATE BEFORE\n");
        return EARLIER_TIME;
    }else if(day < 0 && sec < 0){
        // then to time < from time
        printf("CERT DATE AFTER\n");
        return LATER_TIME;
    }else if(day == 0 && sec > 0){
        // then to time > from time
        printf("CERT DATE BEFORE\n");
        return EARLIER_TIME;
    }else if(day == 0 && sec < 0){
        // then too time < from time
        printf("CERT DATE AFTER\n");
        return LATER_TIME;
    }else{
    /   / same time
        printf("SAME DAY\n");
        return SAME_TIME;
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
        exit(EXIT_FAILURE);
    }

    // retrieve the common name
    X509_NAME_get_text_by_NID(cert_subjects, NID_commonName, subject_cn, BUFFSZ);

    // need to test whether the subject name matches the testing url.

    // first try a strcmp
    if(strcmp(subject_cn,url) == 0){
        // then it is an exact match -- hence we can return true
        return TRUE;
    }else{
        // need to check whether the CN is a wildcard

        if(is_wildcard(subject_cn)){
            // the subject cn is a wild card

            // return the comparison value between the subject_CN and the tested URL
            return comp_wildcard(subject_cn,url);

        }else{
            // if it is not a wild card -- then the CN does not match
            return FALSE;
        }
    }
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
int check_pubkey_ext(X509 *cert){

}
