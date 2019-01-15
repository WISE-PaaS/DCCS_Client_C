CC= gcc -fPIC
CIFLAGS = -I. -I../libopenssl/openssl-1.0.1c/include/openssl
CLFLAGS = -L. -L../libopenssl/openssl-1.0.1c

LDFLAGS = -R. -Wl,-R../libopenssl/openssl-1.0.1c

CDFLAGS = -DLINUX -DLIBMOSQUITTO_EXPORTS -DWITH_TLS -DREAL_WITH_TLS_PSK
LIBS = -lm -ldl -lpthread -lrt -lssl
OBJS = logging_mosq.o memory_mosq.o messages_mosq.o mosquitto.o net_mosq.o read_handle.o read_handle_client.o read_handle_shared.o send_client_mosq.o send_mosq.o socks_mosq.o srv_mosq.o thread_mosq.o time_mosq.o tls_mosq.o util_mosq.o will_mosq.o
all:$(OBJS)
	$(CC) $(CLFLAGS) -shared -o libmosquitto.so $(OBJS) $(LIBS)
logging_mosq.o:
	$(CC) -c logging_mosq.c $(CIFLAGS) $(CDFLAGS)	
memory_mosq.o:
	$(CC) -c memory_mosq.c $(CIFLAGS) $(CDFLAGS)
messages_mosq.o:
	$(CC) -c messages_mosq.c $(CIFLAGS) $(CDFLAGS)
mosquitto.o:
	$(CC) -c mosquitto.c $(CIFLAGS) $(CDFLAGS)	
net_mosq.o:
	$(CC) -c net_mosq.c $(CIFLAGS) $(CDFLAGS)		
read_handle.o:
	$(CC) -c read_handle.c $(CIFLAGS) $(CDFLAGS)	
read_handle_client.o:
	$(CC) -c read_handle_client.c $(CIFLAGS) $(CDFLAGS)	
read_handle_shared.o:
	$(CC) -c read_handle_shared.c $(CIFLAGS) $(CDFLAGS)		
send_client_mosq.o:
	$(CC) -c send_client_mosq.c $(CIFLAGS) $(CDFLAGS)		
send_mosq.o:
	$(CC) -c send_mosq.c $(CIFLAGS) $(CDFLAGS)	
socks_mosq.o:
	$(CC) -c socks_mosq.c $(CIFLAGS) $(CDFLAGS)
srv_mosq.o:
	$(CC) -c srv_mosq.c $(CIFLAGS) $(CDFLAGS)		
thread_mosq.o:
	$(CC) -c thread_mosq.c $(CIFLAGS) $(CDFLAGS)	
time_mosq.o:
	$(CC) -c time_mosq.c $(CIFLAGS) $(CDFLAGS)
tls_mosq.o:
	$(CC) -c tls_mosq.c $(CIFLAGS) $(CDFLAGS)	
util_mosq.o:
	$(CC) -c util_mosq.c $(CIFLAGS) $(CDFLAGS)	
will_mosq.o:
	$(CC) -c will_mosq.c $(CIFLAGS) $(CDFLAGS)		

clean:
	rm -rf *.o
clear:
	rm -rf *.o libmosquitto.so