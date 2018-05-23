#include "helpers.h"

// reconstruct a full path from the base_path and the relative paths
char *reconstruct_full_path(const char *base_path, const char *relative_path){
    // get the size of the full path
    int length = 0;
    // add 1 due to the additon of the '/'
    length = strlen(base_path) + strlen(relative_path) + 1;

    //allocate memory - +1 for '\0'
    char *result = (char*)malloc(sizeof(char)*(length+1));
    if(result == NULL){
        fprintf(stderr,"ERROR: Could not allocate memory for full path\n");
        return NULL;
    }
    // clear the bits in the allocated memory space
    memset(result,0,length+1);

    int i = 0;
    int result_i = 0;
    // add the base_pathpath to the result string
    while(base_path[i] != '\0'){
        result[result_i++] = base_path[i++];
    }

    // add the delimiter to the path
    result[result_i++] = '/';

    // add the relative path to the result string
    i = 0;
    while(relative_path[i] != '\0'){
        result[result_i++] = relative_path[i++];
    }

    // null-byte terminate the result string
    result[result_i] = '\0';

    return result;
}

// compare the from date
int compare_ASN1_TIMES(ASN1_TIME *from, ASN1_TIME *to){

    int comp_day, comp_sec;

    if(!ASN1_TIME_diff(&comp_day, &comp_sec, from, to)){
        fprintf(stderr,"ERROR: Time is not in correct ASN1 time format\n");
        exit(EXIT_FAILURE);
    }

    // if we get here, we can begin to check the day and sec values
    // if the day difference is negative, then the current day is
    // later than the cert before time then day is > 0

    if(comp_day > 0 && comp_sec > 0){
        // then to time > from time
        // printf("CERT DATE BEFORE\n");
        return LATER_TIME;
    }else if(comp_day < 0 && comp_sec < 0){
        // then to time < from time
        // printf("CERT DATE AFTER\n");
        return EARLIER_TIME;
    }else if(comp_day == 0 && comp_sec > 0){
        // then to time > from time
        // printf("CERT DATE BEFORE\n");
        return LATER_TIME;
    }else if(comp_day == 0 && comp_sec < 0){
        // then too time < from time
        // printf("CERT DATE AFTER\n");
        return EARLIER_TIME;
    }else{
        // same time
        // printf("SAME DAY\n");
        return SAME_TIME;
    }

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
