#include "checkers.h"

#define SUCCESS 1
#define FAILURE -1

int verify_certificate(const char *cert_path, const char *url);

int process_certificate_input(const char *input_path);

char *reconstruct_full_path(const char *absolute, const char *relative_path);
