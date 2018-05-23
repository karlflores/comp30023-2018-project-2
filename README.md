# SSL Certificate Checking

### This program implements basic SSL certificate checking using openSSL libraries in C.
```
    usage: ./certcheck [path_to_input_file]
```

The input file must be in the form of a csv file with following format:
```
    example_cert.crt,url_to_test
```

The program produces an file which contains the output of each certificate tested in the form of a csv file "output.csv" formatted as such:
```
    example_cert.crt,url_to_test,validity

    validity: {1 = Valid Certificate , 0 = Invalid Certificate}
```

#### The following fields are validated:
* Not Before Date
* Not After Date
* Common Name - Domain Name
    -  incl. Subject Alternative Name if Domain Name is not a direct match
* RSA Minimum Key Length of 2048 bits
* RSA extensions
    - Basic Constraints (CA:FALSE)
    - Extended Key Usage (TLS Web Server Authentication)

### Updates:
- All main function calls for checking have been implemented, all that is needed is checking and the write up of the rest of the program.
- Program seems to be working correctly -- it produces the same output as the sample output when the input is sample_input.csv
- No more memory leaks -- relevant structures are now freed as neccessary and preallocated memory has been freed when not in use
- Changed the way that the program handles base paths -- instead of looking for the first slash in the relative path, we now look for the last slash in the relative path. This means it can handle nested folders, whereas when we were tokenising the relative path by '/', we were only getting the first folder.
- Added a debug file (debug.out) which breaks down each of the input files and the certificates, and prints the verification of each field in the certificate against the input url/system. This made it easier to work out which of my functions were working as expected.
