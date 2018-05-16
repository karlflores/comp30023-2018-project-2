#include "certificates.h"

int verify_certificate(const char *cert_path, const char *url){

    BIO *certificate_bio = NULL;
    X509 *cert = NULL;

    STACK_OF(X509_EXTENSION) * ext_list;

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
        printf("NOT BEFORE: FALSE\n");
    }else{
        printf("NOT BEFORE: TRUE\n");
    }
    if(check_not_after(cert) == FALSE){
        authenticated = FALSE;
        printf("NOT AFTER: FALSE\n");
    }else{
        printf("NOT AFTER: TRUE\n");
    }

    if(!check_common_name(cert, url)){
        authenticated = FALSE;
        printf("CN: FALSE\n");
    }else{
        printf("CN: TRUE\n");
    }

    if(!check_pubkey_length(cert)){
        authenticated = FALSE;
        printf("PUBKEY LEN: FALSE\n");
    }else{
        printf("PUBKEY LEN: TRUE\n");
    }

    if(!check_ext_key_usage(cert)){
        authenticated = FALSE;
        printf("EXT KEY USAGE: FALSE\n");
    }else{
        printf("EXT KEY USAGE: TRUE\n");
    }

    if(check_basic_constraints(cert) == FALSE){
        authenticated = FALSE;
        printf("KEY BASIC CONSTRAINTS: FALSE\n");
    }else{
        printf("KEY BASIC CONSTRAINTS: TRUE\n");
    }


    // if the certificate is autheticated, therefore all the tests above would have been true
    return authenticated;
}

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

    // need to process the input file to see if it is within another folder -- if it is, we must get that path to the folder
    char *absolute = (char*)malloc(sizeof(char)*BUFFSZ);
    if(absolute == NULL){
        fprintf(stderr,"ERROR: Can't allocate memory\n");
        exit(EXIT_FAILURE);
    }

    if(strstr(input_path,"/")==NULL){
        // then we are opening a file in the directory that we are in currently. Therefore we don't need to reconstruct a path,
        absolute = NULL;

    }else{
        // need to process the input_path
        char temp[BUFFSZ];
        memset(temp,0,BUFFSZ);

        strcpy(temp,input_path);

        char *tk;
        char *sv;
        // first is the aboslute path
        tk = strtok_r(temp,"/",&sv);
        strcpy(absolute,tk);

    }
    printf("ABSOLUTE: %s\n",absolute);
    // process each input until the file ends
    char buffer[BUFFSZ];
    char cert_path[BUFFSZ];
    char url[BUFFSZ];
    int autheticated;
    char *token;
    char *save;
    char delim[2] = ",";
    while(fscanf(input, "%s\n",buffer) != EOF){
        // tokenise the input
        token = strtok_r(buffer,delim,&save);

        // the first is the cert_path
        strcpy(cert_path,token);

        // get the next token -- this is the url
        token = strtok_r(NULL,delim,&save);
        strcpy(url,token);

        printf("CERT PATH: %s\nURL: %s\n",cert_path,url);
        // check the certificate

        if(absolute == NULL){
            autheticated = verify_certificate(cert_path, url);
        }else{
            char *cert_full_path = reconstruct_full_path(absolute,cert_path);
            autheticated = verify_certificate(cert_full_path, url);
        }

        //write result to the output
        fprintf(output,"%s,%s,%d\n",cert_path,url,autheticated);

        // reset the buffers before we read a new line
        memset(cert_path,0,BUFFSZ);
        memset(url,0,BUFFSZ);
        memset(buffer,0,BUFFSZ);
        printf("\n");
    }

    fclose(input);
    fclose(output);
    printf("FINIShED\n");
    return SUCCESS;

}

// reconstruct a full path from the absolute and the relative paths
char *reconstruct_full_path(const char *absolute, const char *relative_path){
    // get the size of the full path
    int length = 0;
    // add 1 due to the additon of the '/'
    length = strlen(absolute) + strlen(relative_path) + 1;

    //allocate memory
    char *result = (char*)malloc(sizeof(char)*(length+1));
    memset(result,0,length+1);

    int i = 0;
    int result_i = 0;
    // add the absolute path to the result string
    while(absolute[i] != '\0'){
        result[result_i++] = absolute[i++];
    }

    // add the delimiter to the path
    result[result_i++] = '/';

    // add the relative path to the result string
    i = 0;
    while(result[i] != '\0'){
        result[result_i++] = relative_path[i++];
    }

    // null-byte terminate the result string
    result[result_i] = '\0';

    return result;
}
