#include <stdio.h>  //printf
#include <string.h> //strlen
#include <stdlib.h> //malloc

#include "DNS_Encode.h"

int to_Qname(unsigned char* qname, unsigned char* packet, int len_packet)
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


info_qnames to_Qnames(unsigned char** qnames, unsigned char* msg, int len_msg)
{
	int run_msg = 0;
	int run_qnames = 0;

	info_qnames info;
	info.nb_packets = 0;

	while (run_msg < len_msg)
	{
		if (len_msg-run_msg >= 250)
		{
			info.last_offset = to_Qname(qnames[run_qnames], msg+run_msg, 250);
			run_msg += 250;
		}
		else
		{
			info.last_offset = to_Qname(qnames[run_qnames], msg+run_msg, len_msg-run_msg);
			run_msg = len_msg;
		}
		run_qnames++;
		info.nb_packets++; 
	}
	return info;
}



int from_Qname(unsigned char* msg, unsigned char* qname, int len_qname) 
{   
	int run_msg = 0;
	int run_qname = 0;
	int run_label = 1;

	while (run_qname < len_qname)
	{
		while (run_label <= qname[run_qname])
		{
			msg[run_msg] = qname[run_qname+run_label];
			run_label++;
			run_msg++;
		}
		run_qname += run_label;
		
		if (run_qname != len_qname)
			msg[run_msg] = '.';
		run_label = 1;
		run_msg++;
	}
	return run_msg-1;
}


// testing purposes (comment include files)
int main(int argc, char* argv[])
{
    unsigned char msg[1024];

    for (int i=0; i<1000; i++)
    	msg[i] = 1;
    msg[1000] = '\0';

	/*
	printf("Enter the msg to encode: ");
	fgets(msg, 1024, stdin);

	// Remove trailing newline, if there is.
	if ((strlen(msg) > 0) && (msg[strlen(msg)-1] == '\n'))
		msg[strlen(msg)-1] = '\0';
	*/

	unsigned char **qnames = malloc(16); 
	for (int i=0; i<16; i++)
		qnames[i] = malloc(256);

	printf("Original = (1000 bytes)\n");

	for (int i=0; i<1000; i++)
		printf("%d", msg[i]);
	printf("\n");
	
	info_qnames info = to_Qnames(qnames, msg, strlen(msg)); 
	printf("Encoded = (%d packets, ", info.nb_packets);

	if (info.last_offset == 256)
		printf("%d of 256 bytes", info.nb_packets);
	else
		printf("%d of 256 bytes, 1 of %d bytes)\n", info.nb_packets-1, info.last_offset);
	
	for (int i=0; i<info.nb_packets-1; i++)
	{	
		for (int j=0; j<256; j++)
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
	
	//for (int i=0; i<16; i++)
	//	free(qnames[i]);
	//free(qnames);
	
	/*
	int msg_len = from_Qname(msg, dns, offset-1);

	printf("Decoded = (%d bytes) %.*s\n", msg_len, msg_len, msg);
	*/
	return 0;
}