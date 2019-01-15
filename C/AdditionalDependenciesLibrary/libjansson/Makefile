CC= gcc -fPIC
CIFLAGS = -I.			
CLFLAGS = -L.

CDFLAGS = -DLINUX -DHAVE_STDINT_H
LIBS = -lm -ldl -lpthread
OBJS = dump.o error.o hashtable.o hashtable_seed.o load.o memory.o pack_unpack.o strbuffer.o strconv.o utf.o value.o

all:$(OBJS)
	$(CC) $(CLFLAGS) -shared -o libjansson.so $(OBJS) $(LIBS)
dump.o:
	$(CC) -c dump.c $(CIFLAGS) $(CDFLAGS)
error.o:
	$(CC) -c error.c $(CIFLAGS) $(CDFLAGS)
hashtable.o:
	$(CC) -c hashtable.c $(CIFLAGS) $(CDFLAGS)
hashtable_seed.o:
	$(CC) -c hashtable_seed.c $(CIFLAGS) $(CDFLAGS)
load.o:
	$(CC) -c load.c $(CIFLAGS) $(CDFLAGS)
memory.o:
	$(CC) -c memory.c $(CIFLAGS) $(CDFLAGS)
pack_unpack.o:
	$(CC) -c pack_unpack.c $(CIFLAGS) $(CDFLAGS)
strbuffer.o:
	$(CC) -c strbuffer.c $(CIFLAGS) $(CDFLAGS)
strconv.o:
	$(CC) -c strconv.c $(CIFLAGS) $(CDFLAGS)
utf.o:
	$(CC) -c utf.c $(CIFLAGS) $(CDFLAGS)
value.o:
	$(CC) -c value.c $(CIFLAGS) $(CDFLAGS)
clean:
	rm -rf *.o
clear:
	rm -rf *.o libjansson.so
