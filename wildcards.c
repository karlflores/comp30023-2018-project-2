#include "wildcards.h"
/*
* We assume that the certificates are valid and the wildcards are always
* Such that the wild card only occurs in the first entry:
* Such as: ------ *.example.com   |   f*.example.com   |   *f.example.com
*                 f*o.example.com |
*
* We also assume that the Name www.example.com is not the same as
* example.com and that the SAN *.example.com is valid for
* www.example.com but not example.com
*/

// compare a wild-card url to a url
int comp_wildcard(const char *wildcard, const char *url){
    // copy the wildcard and url
    char wildcard_copy[BUFFSZ];
    char url_copy[BUFFSZ];

    strcpy(wildcard_copy, wildcard);
    strcpy(url_copy, url);

    // we assume that wildcard is a valid wildcard input
    // therefore we just need to go through token by token
    // and check whether it matches the format

    // before we tokenise each of the wildcard and url, we cna check how many "." occur in each of the URL -- if they do not match, therefore
    // they are not equivalent to each other.
    int wc_periods = count_period(wildcard_copy);
    int url_periods = count_period(url_copy);

    // if they do not contain the same number of periods, therefore, they
    // are not equivalent
    if(wc_periods != url_periods){
        printf("WHY IS THIS FALSE\n");
        return FALSE;
    }

    // get the first token of both the url and the wildcard
    int token_index = 0;
    char separator[2] = ".";
    char wc[2] = "*";
    char *token_wc;
    char *save_wc;
    char *save_url;
    char *token_url;
    int result;

    // tokenise each of the wildcard and also the testing url
    token_wc = strtok_r(wildcard_copy, separator, &save_wc);
    token_url = strtok_r(url_copy, separator, &save_url);

    printf("----------------------\n");
    printf("%s %s\n",token_wc, token_url);

    // are the two paths equivalent -- assume this to be true at first
    int equivalent = TRUE;

    // step through each token
    while(token_wc != NULL && token_url != NULL){
        // process the first token
        if(token_index == 0){
            // process the wildcard

            /*
            Need to test
            *.example.com www.example.com -- TRUE

            f*.example.com fooooooo.example.com -- TRUE

            f*b.example.com foooobar.example.com -- TRUE
            *b.example.com fooob.example.com -- TRUE
            */

            // case 1 -- *. -- therefore always return true
            if(strcmp(token_wc,"*") == 0){
                equivalent = TRUE;
                printf("%s %s\n",token_wc, token_url);
            }else{
                // need to check if it is in the form *f, f* or f*b
                if(token_wc[0] == '*'){
                    // then it is in the form *f -- we just need to compare the portion after the asterisk
                    result = compare_after_wc(token_wc,token_url);

                    // if the two are not equal, then we return false
                    if(result == FALSE){
                        return FALSE;
                    }

                    // else we continue with checking the rest of the fields in the URL and Wildcard


                }else if(token_wc[strlen(token_wc)-1] == '*'){
                    // then it is in the form f*
                    result = compare_before_wc(token_wc,token_url);

                    // if the two are not equal, then we return false
                    if(result == FALSE){
                        return FALSE;
                    }

                }else{
                    // then it is in the form f*b;

                    // first lets check the portion before the wildcard
                    result = compare_after_wc(token_wc,token_url);

                    // if the two are not equal, then we return false
                    if(result == FALSE){
                        return FALSE;
                    }

                    // if the result is not false, then we can check the portion after the asterisk
                    result = compare_after_wc(token_wc,token_url);

                    // if the two are not equal, then we return false
                    if(result == FALSE){
                        return FALSE;
                    }

                    // else, we can continue to check the result of the fields in the paths

                }
          }

        }else{
            // else we just need to step through the index compare the tokens -- if they are equal, then we do nothing, but if they are not equal then the wildcard url and the given url are not equivalent since their fields do not match
            if(strcmp(token_wc, token_url) != 0){
                equivalent = FALSE;
            }
            // printf("%s %s\n",token_wc, token_url);
        }

        // get the next tokens
        token_wc = strtok_r(NULL, separator, &save_wc);
        token_url = strtok_r(NULL, separator, &save_url);
        printf("%s %s\n",token_wc, token_url);
        token_index++;
    }

    // return if the wildcard path and the url path are equivalent
    return equivalent;

}

// checks if a URL is a wildcard
int is_wildcard(const char *url){

    // copy the url
    char url_copy[BUFFSZ];
    strcpy(url_copy,url);
    // check what index the wildcard is at
    int index = -1;
    char separator[2] = ".";
    char wc[2] = "*";
    char *save_wc;
    char *token;

    token = strtok_r(url_copy,separator, &save_wc);

    // if the first token contains the wildcard, therefore it is a wildcard url
    // if the token contains w, then it is the index of the wild card
    if(strstr(token, wc) != NULL){

        // need to free the relevant structures
        return TRUE;
    }else{
        return FALSE;
    }

    // if we get down here, therefore the URL is not a wildcard
    return FALSE;
}

// count the number of periods in a url
int count_period(const char *url){
    int num = 0;

    for(int i = 0; i < strlen(url); i++){
        // count the number of periods
        if(url[i] == '.'){
            num++;
        }
    }
    // return the number of periods
    return num;
}

// compare the token -- the portion before the asterisk
int compare_before_wc(char *token_wc,char *token_url){
    // then it is in the form f*
    // we can compare from the end of the string
    int offset = 0;
    // iterate through the token while we do not reach the wildcard value
    while(token_wc[offset] != '*'){
        // if the end values are not equal, then it is not equal

        if(token_wc[offset] != token_url[offset]){
            return FALSE;
        }
        offset++;
        // we do not care what is at the back of the *
    }

    return TRUE;
}

// compare the token -- the portion after the asterisk
int compare_after_wc(char *token_wc,char *token_url){
    // then it is in the form *f

    // we can compare from the end of the string
    int i_wc = strlen(token_wc)-1;
    int i_url = strlen(token_url)-1;

    // adjust by offset
    int offset = 0;

    // iterate through the token while we do not reach the wildcard value
    while(token_wc[i_wc-offset] != '*'){
        // if the end values are not equal, then it is not equal

        if(token_wc[i_wc-offset] != token_url[i_url-offset]){
          return FALSE;
        }
        offset++;
        // we do not care what is at the front of the *
    }

    // assume if we get to this point, that the two are TRUE
    return TRUE;

}
