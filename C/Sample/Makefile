CC= gcc -fPIC
CIFLAGS = -I. -I../AdditionalDependenciesLibrary/libopenssl/openssl-1.0.1c/include/openssl \
		-I../AdditionalDependenciesLibrary/libmosquitto \
		-I../AdditionalDependenciesLibrary/libjansson \
		-I../SDK

CLFLAGS = -L. -L../AdditionalDependenciesLibrary/libopenssl/openssl-1.0.1c \
		-L../AdditionalDependenciesLibrary/libmosquitto \
		-L../AdditionalDependenciesLibrary/libjansson \
		-L../SDK

LDFLAGS = -Wl,-rpath='$$ORIGIN',-rpath='../SDK',-rpath='../AdditionalDependenciesLibrary/libmosquitto',-rpath='../AdditionalDependenciesLibrary/libjansson',-rpath='../AdditionalDependenciesLibrary/libopenssl/openssl-1.0.1c'

CDFLAGS = -DLINUX
LIBS = -lm -ldl -lpthread -lrt -lssl -lcrypto -lmosquitto -ljansson -ldccssdk
OBJS = main.o

all:$(OBJS)
	$(CC) $(CLFLAGS) $(LDFLAGS) -o main $(OBJS) $(LIBS)
main.o:
	$(CC) -c main.c $(CIFLAGS) $(CDFLAGS)
clean:
	rm -rf *.o
clear:
	rm -rf *.o main