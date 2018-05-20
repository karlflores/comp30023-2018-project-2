#include "certificates.h"

// Function to verify the certificate and the url against the required fields
int verify_certificate(const char *cert_path, const char *url){

    BIO *certificate_bio = NULL;
    X509 *cert = NULL;

    // STACK_OF(X509_EXTENSION) * ext_list;

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    //Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, cert_path))){
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }

    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))){
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }

    // Now verify the certificate
    int authenticated = TRUE;

    // step through each of the checkers
    if(check_not_before(cert) == FALSE){
        authenticated = FALSE;
        // printf("NOT BEFORE: FALSE\n");
    }else{
        // printf("NOT BEFORE: TRUE\n");
    }
    if(check_not_after(cert) == FALSE){
        authenticated = FALSE;
        // printf("NOT AFTER: FALSE\n");
    }else{
        // printf("NOT AFTER: TRUE\n");
    }

    if(!check_common_name(cert, url)){
        authenticated = FALSE;
        // printf("CN: FALSE\n");
    }else{
        // printf("CN: TRUE\n");
    }

    if(!check_pubkey_length(cert)){
        authenticated = FALSE;
        // printf("PUBKEY LEN: FALSE\n");
    }else{
        // printf("PUBKEY LEN: TRUE\n");
    }

    if(!check_ext_key_usage(cert)){
        authenticated = FALSE;
        // printf("EXT KEY USAGE: FALSE\n");
    }else{
        // printf("EXT KEY USAGE: TRUE\n");
    }

    if(check_basic_constraints(cert) == FALSE){
        authenticated = FALSE;
        // printf("KEY BASIC CONSTRAINTS: FALSE\n");
    }else{
        // printf("KEY BASIC CONSTRAINTS: TRUE\n");
    }


    // if the certificate is autheticated, therefore all the tests
    // above would have been true
    X509_free(cert);
    BIO_free_all(certificate_bio);
    return authenticated;
}

// process the whole input file
int process_certificate_input(const char *input_path){
    // create the output file
    FILE *output = fopen("output.csv","w");

    if(output == NULL){
        fprintf(stderr,"ERROR: Can't create output.txt\n");
        return FAILURE;
    }
    //read in the input file to analyse
    FILE *input = fopen(input_path, "r");
    if(input == NULL){
        fprintf(stderr,"ERROR: Can't open input.txt\n");
        return FAILURE;
    }

    // need to process the input file to see if it is within another
    // folder -- if it is, we must get that path to the folder
    char *base_path= (char*)malloc(sizeof(char)*BUFFSZ);
    if(base_path== NULL){
        fprintf(stderr,"ERROR: Can't allocate memory\n");
        exit(EXIT_FAILURE);
    }

    if(strstr(input_path,"/")==NULL){
        // then we are opening a file in the directory that we are in
        //currently. Therefore we don't need to reconstruct a path,
        //free(base_path);

        // set the path to NULL
        base_path= NULL;

    }else{
        // need to process the input_path
        char temp[BUFFSZ];
        memset(temp,0,BUFFSZ);

        strcpy(temp,input_path);

        char *tk;
        char *sv;
        // first is the aboslute path
        tk = strtok_r(temp,"/",&sv);
        strcpy(base_path,tk);

    }
    // printf("base_path: %s\n",base_path);
    // process each input until the file ends
    char buffer[BUFFSZ];
    char cert_path[BUFFSZ];
    char url[BUFFSZ];
    int autheticated;
    char *token;
    char *save;
    char delim[2] = ",";
    char *cert_full_path;
    while(fscanf(input, "%s\n",buffer) != EOF){
        // tokenise the input
        token = strtok_r(buffer,delim,&save);

        // the first is the cert_path
        strcpy(cert_path,token);

        // get the next token -- this is the url
        token = strtok_r(NULL,delim,&save);
        strcpy(url,token);

        // printf("CERT PATH: %s\nURL: %s\n",cert_path,url);
        // check the certificate

        if(base_path== NULL){
            autheticated = verify_certificate(cert_path, url);
        }else{
            cert_full_path = reconstruct_full_path(base_path,cert_path);
            autheticated = verify_certificate(cert_full_path, url);

            // free the path once we are done with it
            // free(cert_full_path);
        }

        //write result to the output
        fprintf(output,"%s,%s,%d\n",cert_path,url,autheticated);

        // reset the buffers before we read a new line
        memset(cert_path,0,BUFFSZ);
        memset(url,0,BUFFSZ);
        memset(buffer,0,BUFFSZ);
        // printf("\n");
    }

    fclose(input);
    fclose(output);
    // printf("FINIShED\n");
    return SUCCESS;

}
