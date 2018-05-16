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

[validity: 1 = Valid Certificate , 0 = Invalid Certificate]
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

### TODO:
* Further validation of each checker function
* Check whether www.example.com is equal to example.com when checking the Common name
* validation of the Subject Alternative Name -- need to check if it is always in the form \[DNS: <path> + ", "\]

### Completed:
* All main function calls for checking have been implemented, all that is needed is checking and the write up of the rest of the program.
* Program seems to be working correctly -- it produces the same output as the sample output when the input is sample_input.csv
