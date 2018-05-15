# SSL Certificate Checking

### This program implements basic SSL certificate checking using openSSL libraries in C.

#### The following fields are validated:
* Not Before Date
* Not After Date
* Common Name - Domain Name
    -  incl. Subject Alternative Name if Domain Name is not a direct match
* RSA Minimum Key Length of 2048 bits
* RSA extensions
    - Basic Constraints (CA:FALSE)
    - Extended Key Usage (TLS Web Server Authentication)

### TODO:
* Validation of each checker function
* Check whether www.example.com is equal to example.com when checking the Common name
* validation of the Subject Alternative Name -- need to check if it is always in the form \[DNS: <path> + ", "\]
* Need to write the input and output functions for certificates
* Need to write the overall main method for the program
* Need to validate if my wildcard checker function is working correctly.

### Completed:
* All main function calls for checking have been implemented, all that is needed is checking and the write up of the rest of the program.
