#include "certificates.h"
#include "checkers.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ARGC_SIZE 2

/*
* AUTHOR: KARL FLORES (760493)
* LAST MODIFIED: 24/5/2018
*
* Main function -- implement the command line input
*/
int main(int argc, char **argv){
    // assert the command line arguments
    if(argc != ARGC_SIZE){
        fprintf(stdout, "usage: ./certcheck [pathToTestFile]\n");
        exit(EXIT_FAILURE);
    }

    // get the filepath of the input file from the input
    char file_path[BUFFSZ];
    strcpy(file_path, argv[1]);
    // printf("INPUT: %s\n",file_path);

    // now process the input
    if(process_certificate_input(file_path) < 0){
        fprintf(stderr, "ERROR: Can't process input file\n");
        return FAILURE;
    }
    // exit
    return SUCCESS;
}
