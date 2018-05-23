#include "certificates.h"

// Function to verify the certificate and the url against the required fields
int verify_certificate(const char *cert_path, const char *url){
    // debug text file
    FILE *debug = fopen("debug.out","a");
    fprintf(debug,"----------------------------\n");
    fprintf(debug,"%s\n%s\n",url,cert_path);
    fprintf(debug,"****************************\n");

    // Set up the X509 certificate structures
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;

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

    // step through each of the checkers -- this prints to a debug file as well
    // as altering the authenticated flag

    if(check_not_before(cert) == TRUE){
        fprintf(debug,"NOT BEFORE:             TRUE\n");
    }else{
        fprintf(debug,"NOT BEFORE:            FALSE\n");
        authenticated = FALSE;
    }

    if(check_not_after(cert) == TRUE){
        fprintf(debug,"NOT AFTER:              TRUE\n");
    }else{
        fprintf(debug,"NOT AFTER:             FALSE\n");
        authenticated = FALSE;
    }

    if(check_common_name(cert, url) == TRUE){
        fprintf(debug,"COMMON NAME/SAN:        TRUE\n");
    }else{
        fprintf(debug,"COMMON NAME/SAN:       FALSE\n");
        authenticated = FALSE;
    }

    if(check_pubkey_length(cert) == TRUE){
        fprintf(debug,"PUBKEY LENGTH:          TRUE\n");
    }else{
        fprintf(debug,"PUBKEY LENGTH:         FALSE\n");
        authenticated = FALSE;
    }

    if(check_ext_key_usage(cert) == TRUE){
        fprintf(debug,"EXT KEY USAGE:          TRUE\n");
    }else{
        fprintf(debug,"EXT KEY USAGE:         FALSE\n");
        authenticated = FALSE;
    }

    if(check_basic_constraints(cert) == TRUE){
        fprintf(debug,"KEY BASIC CONSTRAINTS:  TRUE\n");
    }else{
        fprintf(debug,"KEY BASIC CONSTRAINTS: FALSE\n");
        authenticated = FALSE;
    }


    // if the certificate is autheticated, therefore all the tests
    // above would have been true
    X509_free(cert);
    BIO_free_all(certificate_bio);

    // close the debug file
    fprintf(debug,"AUTHENTICATED:            %d\n",authenticated);
    fprintf(debug,"----------------------------\n\n");
    fclose(debug);

    // clean up the initialised files
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    // return whether it is autheticated or not
    return authenticated;
}

// process the whole input file
int process_certificate_input(const char *input_path){
    // create the output file
    FILE *output = fopen("output.csv","w");
    if(output == NULL){
        fprintf(stderr,"ERROR: Can't create output.csv\n");
        return FAILURE;
    }
    // -------------------------------------------------------------------------
    // create the debug file -- immediately close it so that the verify function
    // can access it
    FILE *debug = fopen("debug.out","w");
    if(debug == NULL){
        fprintf(stderr,"ERROR: Can't create debug.out\n");
        return FAILURE;
    }
    fclose(debug);
    // -------------------------------------------------------------------------

    //read in the input file to analyse
    FILE *input = fopen(input_path, "r");
    if(input == NULL){
        fprintf(stderr,"ERROR: Can't open input file\n");
        return FAILURE;
    }

    // need to process the input file to see if it is within another
    // folder -- if it is, we must get that path to the folder
    char *base_path = (char*)malloc(sizeof(char)*BUFFSZ);
    if(strstr(input_path,"/")==NULL){
        // then we are opening a file in the directory that we are in
        //currently. Therefore we don't need to reconstruct a path,
        // free the allocate memory if the input path does not contain a
        // sub path
        free(base_path);

        // set the path to NULL
        base_path= NULL;

    }else{
        // need to process the input_path
        char temp[BUFFSZ];
        memset(temp,0,BUFFSZ);
        strcpy(temp,input_path);

        // need to find the last / in the relative path
        // the relative path

        int last_slash_index;

        // METHOD 2 -- this should handle nested paths not just a single path
        for(int i = 0;i < strlen(temp);i++){
            if(temp[i] == '/'){
                last_slash_index = i;
            }
        }
        // set the last slash to be '\0' -- terminate the string here
        temp[last_slash_index] = '\0';

        // copy it into the base path memory
        strcpy(base_path,temp);

    }

    // process each input until the file ends
    char buffer[BUFFSZ];
    char cert_path[BUFFSZ];
    char url[BUFFSZ];
    int autheticated;
    char *token;
    char *save;
    char *cert_full_path;
    char delim[2] = ",";

    // read each line of the file
    while(fscanf(input, "%s\n",buffer) != EOF){
        // tokenise the input
        token = strtok_r(buffer,delim,&save);

        // the first is the cert_path
        strcpy(cert_path,token);

        // get the next token -- this is the url
        token = strtok_r(NULL,delim,&save);
        strcpy(url,token);

        // check the certificate

        // if there is no subpath in the input path then the cert_path is
        // the full path
        if(base_path== NULL){
            // now we can verify the input against the certificate
            autheticated = verify_certificate(cert_path, url);

        }else{
            // if there is a sub path, reconstruct the full path from the
            // base path and cert_path
            cert_full_path = reconstruct_full_path(base_path,cert_path);

            // check if the memory has not been allocated
            if(cert_full_path == NULL){
                fprintf(stderr,"ERROR: Can't free path memory.\n");

                // free the base path if this is the case
                if(!base_path){
                    free(base_path);
                }
                fclose(input);
                fclose(output);
                return FAILURE;
            }

            //  now verify the input against the certificate
            autheticated = verify_certificate(cert_full_path, url);

            // check if we have a full_path to free
            if(cert_full_path != NULL){
                // free the path once we are done with it, remember to set it back
                // to NULL since malloc does not do this after it is called
                free(cert_full_path);
                cert_full_path = NULL;
            }

        }



        //write result to the output file
        fprintf(output,"%s,%s,%d\n",cert_path,url,autheticated);

        // reset the buffers before we read a new line
        memset(cert_path,0,BUFFSZ);
        memset(url,0,BUFFSZ);
        memset(buffer,0,BUFFSZ);

    }
    // close the files
    fclose(input);
    fclose(output);

    // check if we have a base_path to free
    if(base_path!=NULL){
        free(base_path);
    }

    // if we reach here -- therefore we have read and processed all inputs
    return SUCCESS;

}
