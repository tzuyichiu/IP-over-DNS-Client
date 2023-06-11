#include <stdio.h>	// printf, getpid
#include <string.h> // strlen
#include <stdlib.h> // malloc

#include "DNS_Packet.h"
#include "DNS_flag.h"
#include "DNS_Constructor.h"

void to_qname(unsigned char *qname, unsigned char *packet, int len_packet)
{
	int run_qname = 0;
	int run_label = 1;
	int run_packet = 0;

	qname[run_qname] = 0;
	while (run_packet < len_packet)
	{
		if (run_label < 64)
		{
			qname[run_qname + run_label++] = packet[run_packet++];
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
	qname[run_qname++] = '\0';
}

void msg_to_qnames(unsigned char **qnames, unsigned char *msg, int len_msg)
{
	int run_msg = 0;
	int run_qnames = 0;

	while (run_msg < len_msg)
	{
		if (len_msg - run_msg >= 250)
		{
			to_qname(qnames[run_qnames++], msg + run_msg, 250);
			run_msg += 250;
		}
		else
		{
			to_qname(qnames[run_qnames++], msg + run_msg, len_msg - run_msg);
			run_msg = len_msg;
		}
	}
}

void msg_to_DNSs(DNS_PACKET *dns_packets, int nb_packets, unsigned char *msg, int len_msg)
{
	unsigned char *qnames[nb_packets];

	for (int i = 0; i < nb_packets; i++)
		qnames[i] = malloc(255);

	msg_to_qnames(qnames, msg, len_msg);

	for (int i = 0; i < nb_packets; i++)
	{
		dns_packets[i].header.qr = QR_QUERY;
		dns_packets[i].header.opcode = OPCODE_QUERY;
		dns_packets[i].header.aa = AA_QUERY_NAME;
		dns_packets[i].header.tc = TC_NOT_TRUNCATED;
		dns_packets[i].header.ra = RA_REC_UNAVAILABLE;
		dns_packets[i].header.z = 0;
		dns_packets[i].header.rcode = RCODE_NO_ERROR;
		dns_packets[i].header.qdcount = 1;
		dns_packets[i].header.ancount = 0;
		dns_packets[i].header.nscount = 0;
		dns_packets[i].header.arcount = 0;
		dns_packets[i].question->qtype = QTYPE_A;
		dns_packets[i].question->qclass = CLASS_IN;
		memcpy(dns_packets[i].question->qname, qnames[i], 255);
		free(qnames[i]);
	}
}