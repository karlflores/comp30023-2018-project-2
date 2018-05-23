################################################################
#                                                              #
#                  MAKEFILE FOR CERTCHECK                      #
#                                                              #
################################################################
CC = gcc
CFLAGS = -Wall -std=c99 -g

SRC1 = wildcards.c checkers.c main.c certificates.c helpers.c
OBJ1 = wildcards.o checkers.o main.o certificates.o helpers.o

EXE1 = certcheck

all: $(EXE1)

$(EXE1): $(OBJ1) Makefile
	$(CC) $(CFLAGS) -o $(EXE1) $(OBJ1) -g -lssl -lcrypto

clean:
	rm -f $(OBJ1) $(EXE1)
