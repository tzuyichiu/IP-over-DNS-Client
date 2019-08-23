#include <stdio.h>  //printf
#include <string.h> //strlen
#include <stdlib.h> //malloc

#include "DNS_Encode.h"
#include "DNS_Packet.h"

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

/*
typedef struct {
    int nb_packets;
    int last_offset;
} info_qnames;
*/

info_qnames bytes_to_qnames(unsigned char** qnames, unsigned char* msg, int len_msg)
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



int qname_to_bytes(unsigned char* msg, unsigned char* qname) 
{   
	int run_msg = 0;
	int run_qname = 0;
	int run_label = 1;

	while (qname[run_qname] != '\0')
	{
		while (run_label <= qname[run_qname])
		{
			msg[run_msg] = qname[run_qname+run_label];
			run_label++;
			run_msg++;
		}
		run_qname += run_label;
		
		if (qname[run_qname] == '\0')
			msg[run_msg] = '\0';
		run_label = 1;
	}
	return run_msg;
}


int DNS_to_bytes(unsigned char* bytes, DNS_PACKET dns_packet)
{
    // header
    bytes[0]  		 =	(dns_packet.header->id       >>  8) & 0xFF;
    bytes[1]  		 =	(dns_packet.header->id       >>  0) & 0xFF;

    bytes[2]  		 = ((dns_packet.header->rd 	 	 <<  0) & 0x01) |
               	       ((dns_packet.header->tc       <<  1) & 0x02) |
               	       ((dns_packet.header->aa       <<  2) & 0x04) | 
               		   ((dns_packet.header->opcode   <<  3) & 0x78) |
               		   ((dns_packet.header->qr       <<  7) & 0x80);

    bytes[3]  		 = ((dns_packet.header->rcode    <<  0) & 0x0F) |
               		   ((dns_packet.header->z        <<  4) & 0x70) |
               		   ((dns_packet.header->ra       <<  7) & 0x80);

    bytes[4]  		 =	(dns_packet.header->qdcount  >>  8) & 0xFF;
    bytes[5]  		 =	(dns_packet.header->qdcount  >>  0) & 0xFF;

    bytes[6]  		 =	(dns_packet.header->ancount  >>  8) & 0xFF;
    bytes[7]  		 =	(dns_packet.header->ancount  >>  0) & 0xFF;

    bytes[8]  		 =	(dns_packet.header->nscount  >>  8) & 0xFF;
    bytes[9]  		 =	(dns_packet.header->nscount  >>  0) & 0xFF;

    bytes[10] 		 =	(dns_packet.header->arcount  >>  8) & 0xFF;
    bytes[11] 		 =	(dns_packet.header->arcount  >>  0) & 0xFF;
    
    // question
    int offset = qname_to_bytes(bytes[12], dns_packet.question->qname)
    
    bytes[11+offset] = 	(dns_packet.question->qtype  >>  8) & 0xFF;
    bytes[12+offset] = 	(dns_packet.question->qtype  >>  0) & 0xFF;

    bytes[13+offset] = 	(dns_packet.question->qclass >>  8) & 0xFF;
    bytes[14+offset] = 	(dns_packet.question->qclass >>  0) & 0xFF;

    // answer

    offset += qname_to_bytes(bytes[12], dns_packet.answer->name)
    
    bytes[14+offset] = 	(dns_packet.answer->type 	 >>  8) & 0xFF;
    bytes[15+offset] = 	(dns_packet.answer->type 	 >>  0) & 0xFF;

    bytes[16+offset] = 	(dns_packet.answer->rclass 	 >>  8) & 0xFF;
    bytes[17+offset] = 	(dns_packet.answer->rclass 	 >>  0) & 0xFF;

    bytes[18+offset] = 	(dns_packet.answer->ttl 	 >> 24) & 0xFF;
    bytes[19+offset] = 	(dns_packet.answer->ttl		 >> 16) & 0xFF;
    bytes[20+offset] = 	(dns_packet.answer->ttl 	 >>  8) & 0xFF;
    bytes[21+offset] = 	(dns_packet.answer->ttl 	 >>  0) & 0xFF;

    bytes[22+offset] = 	(dns_packet.answer->rdlength >>  8) & 0xFF;
    bytes[23+offset] = 	(dns_packet.answer->rdlength >>  0) & 0xFF;

    bytes[24+offset] =  dns_packet.answer->rdata;

    return 24 + offset + dns_packet.answer->rdlength;
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
	
	info_qnames info = to_Qnames(qnames, msg, strlen(msg)); 
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
		msg_len += from_Qname(run_msg, qnames[i]);
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