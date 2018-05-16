CC = gcc
CFLAGS = -Wall -std=c99

SRC1 = wildcards.c checkers.c main.c certificates.c
OBJ1 = wildcards.o checkers.o main.o certificates.o

SRC2 = wildcards.c test_wildcards.c
OBJ2 = wildcards.o test_wildcards.o

EXE1 = certcheck
EXE2 = test_wildcard

all: $(EXE1) $(EXE2)

$(EXE1): $(OBJ1) Makefile
	$(CC) $(CFLAGS) -o $(EXE1) $(OBJ1) -g -lssl -lcrypto

$(EXE2): $(OBJ2) Makefile
	$(CC) $(CFLAGS) -o $(EXE2) $(OBJ2) -g -lssl -lcrypto

clean:
	rm -f $(OBJ1) $(EXE1)
	rm -f $(OBJ2) $(EXE2)
