CIFLAGS = -I. -I../AdditionalDependenciesLibrary/libopenssl/openssl-1.0.1c/include/openssl \
		-I../AdditionalDependenciesLibrary/libmosquitto \
		-I../AdditionalDependenciesLibrary/libjansson

CLFLAGS = -L. -L../AdditionalDependenciesLibrary/libopenssl/openssl-1.0.1c \
		-L../AdditionalDependenciesLibrary/libmosquitto \
		-L../AdditionalDependenciesLibrary/libjansson

LDFLAGS = -R. -Wl,-R../libopenssl/openssl-1.0.1c

CDFLAGS = -DLINUX
LIBS = -lm -ldl -lpthread -lssl -lmosquitto -ljansson
OBJS = dccsSDK.o

all:$(OBJS)
	$(CC) $(CLFLAGS) -shared -o libdccssdk.so $(OBJS) $(LIBS)
dccsSDK.o:
	$(CC) -c dccsSDK.c $(CIFLAGS) $(CDFLAGS)
clean:
	rm -rf *.o
clear:
	rm -rf *.o libdccssdk.so
