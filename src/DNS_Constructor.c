#include <stdio.h>  	//printf
#include <string.h> 	//strlen
#include <stdlib.h> 	//malloc
#include <sys/types.h>  //getpid
#include <unistd.h>		//getpid

#include "DNS_Packet.h"
#include "DNS_flag.h"
#include "DNS_Constructor.h"


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


int msg_to_DNSs(DNS_PACKET *dns_packets, unsigned char *msg, int len_msg)
{
	unsigned char *qnames[len_msg/250+1]; 

	for (int i=0; i<len_msg/250+1; i++)
		qnames[i] = malloc(255);

	info_qnames info = msg_to_qnames(qnames, msg, len_msg);

	DNS_PACKET *dns_packet = dns_packets;

	for (int i=0; i<info.nb_packets; i++)
	{
		dns_packet->header.id 		 = getpid();
		dns_packet->header.qr 		 = QR_QUERY;
		dns_packet->header.opcode 	 = OPCODE_QUERY;
		dns_packet->header.aa 		 = AA_QUERY_NAME;
		dns_packet->header.tc 		 = TC_NOT_TRUNCATED;
		dns_packet->header.rd 		 = RD_REC_DESIRED;
		dns_packet->header.ra 		 = RA_REC_UNAVAILABLE;
		dns_packet->header.z 		 = 0;
		dns_packet->header.rcode 	 = RCODE_NO_ERROR;
		dns_packet->header.qdcount   = 1;
		dns_packet->header.ancount   = 0;
		dns_packet->header.nscount   = 0;
		dns_packet->header.arcount   = 0;
		
		memcpy(dns_packet->question->qname, qnames[i], 255);
		
		dns_packet->question->qtype  = QTYPE_A;
		dns_packet->question->qclass = CLASS_IN;

		dns_packet++;
		free(qnames[i]);
	}

	return info.nb_packets;
}