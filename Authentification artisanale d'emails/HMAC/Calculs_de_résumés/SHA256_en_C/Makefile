CC = gcc

INCLUDE = -I/usr/local/include -I/usr/include
LIB = -L/usr/local/lib -L/usr/lib -lm -lssl -lcrypto -g -std=c99 -Wall

all: resumes

resumes: resumes.c
	$(CC) -o resumes $(INCLUDE) resumes.c $(LIB)

clean:
	-rm *.o *~
	-rm resumes

