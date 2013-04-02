CC = gcc
OPENSSLDIR = /usr/local/ssl
LIBCRYPTO = $(OPENSSLDIR)/lib/libcrypto.a
INCLUDES = -I$(OPENSSLDIR)/include -I../openssl-fips-2.0.2/include
CMD = fips-test
OBJS = $(CMD).o

default: fips-test

fips-test: fips-test.o
	FIPSLD_CC=$(CC) $(OPENSSLDIR)/fips-2.0/bin/fipsld -o fips-test $(OBJS) $(LIBCRYPTO) -ldl

fips-test.o: fips-test.c 
	$(CC) -c fips-test.c $(INCLUDES) -L$(OPENSSLDIR) -l$(LIBCRYPTO) -g

clean:
	rm -f $(OBJS) $(CMD) *.o

