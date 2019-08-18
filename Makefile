
all:
	gcc -pthread DNS_Client.c DNS_Query.c DNS_Encode.c DNS_Listen.c DNS_Decode.c -o DNS_Client

clean:
	rm -f DNS_Client
