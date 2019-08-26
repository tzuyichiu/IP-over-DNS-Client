#include <stdio.h>  //printf
#include <string.h> //strlen
#include <stdlib.h> //malloc

#include "DNS_Constructor.h"
#include "DNS_Packet.h"
#include "DNS_flag.h"


int to_qname_format(unsigned char* qname, unsigned char* packet, int len_packet)
{
	int run_qname = 0;
	int run_label = 1;
	int run_packet = 0;

	qname[run_qname] = 0;
	while (run_packet < len_packet)
	{
		if (run_label < 64)
		{
			qname[run_qname+run_label] = packet[run_packet];
			run_packet++;
			run_label++;
			qname[run_qname]++;	
		}
		else
		{
			run_qname += run_label;
			qname[run_qname] = 0;
			run_label = 1;
		}
	}
	run_qname += run_label;
	qname[run_qname] = '\0';
	return run_qname+1;
}

/*
typedef struct {
    int nb_packets;
    int last_offset;
} info_qnames;
*/

info_qnames msg_to_qnames(unsigned char** qnames, unsigned char* msg, int len_msg)
{
	int run_msg = 0;
	int run_qnames = 0;

	info_qnames info;
	info.nb_packets = 0;

	while (run_msg < len_msg)
	{
		if (len_msg-run_msg >= 250)
		{
			info.last_offset = to_qname_format(qnames[run_qnames], msg+run_msg, 250);
			run_msg += 250;
		}
		else
		{
			info.last_offset = to_qname_format(qnames[run_qnames], msg+run_msg, len_msg-run_msg);
			run_msg = len_msg;
		}
		run_qnames++;
		info.nb_packets++; 
	}
	return info;
}


int msg_to_DNSs(DNS_Packet* DNSs, unsigned char* msg, int len_msg)
{
	unsigned char *qnames[len_msg/250+1]; 
	for (int i=0; i<16; i++)
		qnames[i] = malloc(255);

	printf("Original = (1024 bytes)\n");

	for (int i=0; i<1024; i++)
		printf("%d", msg[i]);
	printf("\n");
	
	info_qnames info = msg_to_qnames(qnames, msg, strlen(msg)); 
	printf("Encoded = (%d packets, ", info.nb_packets);

	if (info.last_offset == 255)
		printf("%d of 255 bytes)\n", info.nb_packets);
	else
		printf("%d of 255 bytes, 1 of %d bytes)\n", info.nb_packets-1, info.last_offset);
	
	for (int i=0; i<info.nb_packets-1; i++)
	{	
		for (int j=0; j<255; j++)
		{
			printf("%d", qnames[i][j]);
		}
		printf("\n");
	}
	for (int j=0; j<info.last_offset; j++)
	{
		int i = info.nb_packets-1;
		printf("%d", qnames[i][j]);
	}
	printf("\n");
}


// testing purposes (comment include files)
int main(int argc, char* argv[])
{
    unsigned char msg[1024];

    for (int i=0; i<1024; i++)
    	msg[i] = 1;
    msg[1024] = '\0';

	/*
	printf("Enter the msg to encode: ");
	fgets(msg, 1024, stdin);

	// Remove trailing newline, if there is.
	if ((strlen(msg) > 0) && (msg[strlen(msg)-1] == '\n'))
		msg[strlen(msg)-1] = '\0';
	*/

	unsigned char *qnames[16]; 
	for (int i=0; i<16; i++)
		qnames[i] = malloc(255);

	printf("Original = (1024 bytes)\n");

	for (int i=0; i<1024; i++)
		printf("%d", msg[i]);
	printf("\n");
	
	info_qnames info = msg_to_qnames(qnames, msg, strlen(msg)); 
	printf("Encoded = (%d packets, ", info.nb_packets);

	if (info.last_offset == 255)
		printf("%d of 255 bytes)\n", info.nb_packets);
	else
		printf("%d of 255 bytes, 1 of %d bytes)\n", info.nb_packets-1, info.last_offset);
	
	for (int i=0; i<info.nb_packets-1; i++)
	{	
		for (int j=0; j<255; j++)
		{
			printf("%d", qnames[i][j]);
		}
		printf("\n");
	}
	for (int j=0; j<info.last_offset; j++)
	{
		int i = info.nb_packets-1;
		printf("%d", qnames[i][j]);
	}
	printf("\n");
	
	int msg_len = 0;
	unsigned char* run_msg = msg;

	for (int i=0; i<info.nb_packets; i++)
	{
		msg_len += qname_to_bytes(run_msg, qnames[i]);
		run_msg = msg + msg_len;
	}

	printf("Decoded = (%d bytes)\n", msg_len);

	for (int i=0; i<msg_len; i++)
		printf("%d", msg[i]);
	printf("\n");

	for (int i=0; i<16; i++)
		free(qnames[i]);
	
	return 0;
}