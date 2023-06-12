#include <stdio.h>	// printf
#include <string.h> // strlen
#include <stdlib.h> //malloc

#include "packet.h"
#include "encoder.h"
#include "flag.h"

int msg_to_qname(unsigned char *qname, unsigned char *msg, unsigned char *end)
{
	int max_run = end - msg < QNAME_MAX_SZ - 1 ? end - msg : QNAME_MAX_SZ - 1;
	int run_qname = 0, run_label = 1, run_msg = 0;
	qname[run_qname] = 0;
	while (run_qname + run_label < max_run)
	{
		qname[run_qname]++; // length byte
		qname[run_qname + run_label++] = msg[run_msg++];
		if (run_label > LABEL_MAX_SZ) {
			run_qname += run_label;
			qname[run_qname] = 0;
			run_label = 1;
		}
	}
	qname[max_run] = '\0';
	return run_msg;
}

int qname_to_msg(unsigned char *msg, unsigned char *qname)
{
	int run_msg = 0;
	int run_qname = 0;
	int run_label = 1;

	while (qname[run_qname] != '\0')
	{
		while (run_label <= qname[run_qname])
			msg[run_msg++] = qname[run_qname + run_label++];
		run_qname += run_label;

		if (qname[run_qname] == '\0')
			msg[run_msg] = '\0';
		run_label = 1;
	}
	return run_msg;
}

void msg_to_DNSs(DNS_PACKET **dns_packets, int nb_packets,
								 unsigned char *msg, int len_msg)
{
	unsigned char *p_msg = msg;
	int offset;
	for (int i = 0; i < nb_packets; i++)
	{
		dns_packets[i]->header.qr = QR_QUERY;
		dns_packets[i]->header.opcode = OPCODE_QUERY;
		dns_packets[i]->header.aa = AA_QUERY_NAME;
		dns_packets[i]->header.tc = TC_NOT_TRUNCATED;
		dns_packets[i]->header.ra = RA_REC_UNAVAILABLE;
		dns_packets[i]->header.z = 0;
		dns_packets[i]->header.rcode = RCODE_NO_ERROR;
		dns_packets[i]->header.qdcount = 1;
		dns_packets[i]->header.ancount = 0;
		dns_packets[i]->header.nscount = 0;
		dns_packets[i]->header.arcount = 0;
		dns_packets[i]->question->qtype = QTYPE_A;
		dns_packets[i]->question->qclass = CLASS_IN;
		p_msg += msg_to_qname(dns_packets[i]->question->qname, p_msg, msg + len_msg);
	}
}

int DNS_to_bytes(unsigned char *bytes, DNS_PACKET *dns_packet)
{
	int offset = 0;

	HEADER header = dns_packet->header;
	bytes[offset++] = ((header.id >> 8) & 0xFF);
	bytes[offset++] = ((header.id >> 0) & 0xFF);
	bytes[offset++] = ((header.qr << 7) & 0x80) |
										((header.opcode << 3) & 0x78) |
										((header.aa << 2) & 0x04) |
										((header.tc << 1) & 0x02) |
										((header.rd << 0) & 0x01);
	bytes[offset++] = ((header.ra << 7) & 0x80) |
										((header.z << 4) & 0x70) |
										((header.rcode << 0) & 0x0F);
	bytes[offset++] = ((header.qdcount >> 8) & 0xFF);
	bytes[offset++] = ((header.qdcount >> 0) & 0xFF);
	bytes[offset++] = ((header.ancount >> 8) & 0xFF);
	bytes[offset++] = ((header.ancount >> 0) & 0xFF);
	bytes[offset++] = ((header.nscount >> 8) & 0xFF);
	bytes[offset++] = ((header.nscount >> 0) & 0xFF);
	bytes[offset++] = ((header.arcount >> 8) & 0xFF);
	bytes[offset++] = ((header.arcount >> 0) & 0xFF);

	unsigned char *tmp;

	QUESTION question;
	for (int i = 0; i < header.qdcount; i++)
	{
		question = dns_packet->question[i];
		tmp = question.qname;
		while (*tmp != '\0')
			bytes[offset++] = *(tmp++);
		bytes[offset++] = '\0';

		bytes[offset++] = (question.qtype >> 8) & 0xFF;
		bytes[offset++] = (question.qtype >> 0) & 0xFF;
		bytes[offset++] = (question.qclass >> 8) & 0xFF;
		bytes[offset++] = (question.qclass >> 0) & 0xFF;
	}

	RR answer;
	for (int i = 0; i < header.ancount; i++)
	{
		answer = dns_packet->answer[i];
		unsigned char *tmp = answer.name;
		while (*tmp != '\0')
			bytes[offset++] = *(tmp++);
		bytes[offset++] = '\0';

		bytes[offset++] = (answer.type >> 8) & 0xFF;
		bytes[offset++] = (answer.type >> 0) & 0xFF;
		bytes[offset++] = (answer.rclass >> 8) & 0xFF;
		bytes[offset++] = (answer.rclass >> 0) & 0xFF;
		bytes[offset++] = (answer.ttl >> 24) & 0xFF;
		bytes[offset++] = (answer.ttl >> 16) & 0xFF;
		bytes[offset++] = (answer.ttl >> 8) & 0xFF;
		bytes[offset++] = (answer.ttl >> 0) & 0xFF;
		bytes[offset++] = (answer.rdlength >> 8) & 0xFF;
		bytes[offset++] = (answer.rdlength >> 0) & 0xFF;

		memcpy(bytes + offset, answer.rdata, answer.rdlength);
		offset += answer.rdlength;
	}

	RR authority;
	for (int i = 0; i < dns_packet->header.nscount; i++)
	{
		authority = dns_packet->authority[i];
		unsigned char *tmp = authority.name;
		while (*tmp != '\0')
			bytes[offset++] = *(tmp++);
		bytes[offset++] = '\0';

		bytes[offset++] = (authority.type >> 8) & 0xFF;
		bytes[offset++] = (authority.type >> 0) & 0xFF;
		bytes[offset++] = (authority.rclass >> 8) & 0xFF;
		bytes[offset++] = (authority.rclass >> 0) & 0xFF;
		bytes[offset++] = (authority.ttl >> 24) & 0xFF;
		bytes[offset++] = (authority.ttl >> 16) & 0xFF;
		bytes[offset++] = (authority.ttl >> 8) & 0xFF;
		bytes[offset++] = (authority.ttl >> 0) & 0xFF;
		bytes[offset++] = (authority.rdlength >> 8) & 0xFF;
		bytes[offset++] = (authority.rdlength >> 0) & 0xFF;

		memcpy(bytes + offset, authority.rdata, authority.rdlength);
		offset += authority.rdlength;
	}

	RR additional;
	for (int i = 0; i < header.arcount; i++)
	{
		additional = dns_packet->additional[i];
		tmp = additional.name;
		while (*tmp != '\0')
			bytes[offset++] = *(tmp++);
		bytes[offset++] = '\0';

		bytes[offset++] = (additional.type >> 8) & 0xFF;
		bytes[offset++] = (additional.type >> 0) & 0xFF;
		bytes[offset++] = (additional.rclass >> 8) & 0xFF;
		bytes[offset++] = (additional.rclass >> 0) & 0xFF;
		bytes[offset++] = (additional.ttl >> 24) & 0xFF;
		bytes[offset++] = (additional.ttl >> 16) & 0xFF;
		bytes[offset++] = (additional.ttl >> 8) & 0xFF;
		bytes[offset++] = (additional.ttl >> 0) & 0xFF;
		bytes[offset++] = (additional.rdlength >> 8) & 0xFF;
		bytes[offset++] = (additional.rdlength >> 0) & 0xFF;

		memcpy(bytes + offset, additional.rdata, additional.rdlength);
		offset += additional.rdlength;
	}
	return offset;
}

int bytes_to_DNS(DNS_PACKET *dns_packet, unsigned char *bytes)
{
	HEADER header = dns_packet->header;
	header.id = ((bytes[0] << 8) & 0xFF00) |
							((bytes[1] << 0) & 0xFF);
	header.qr = ((bytes[2] >> 7) & 0x01);
	header.opcode = ((bytes[2] >> 3) & 0x80);
	header.aa = ((bytes[2] >> 2) & 0x01);
	header.tc = ((bytes[2] >> 1) & 0x01);
	header.rd = ((bytes[2] >> 0) & 0x01);
	header.ra = ((bytes[3] >> 7) & 0x01);
	header.z = ((bytes[3] >> 4) & 0x08);
	header.rcode = ((bytes[3] >> 0) & 0x0F);
	header.qdcount = ((bytes[4] << 8) & 0xFF00) |
									 ((bytes[5] << 0) & 0xFF);
	header.ancount = ((bytes[6] << 8) & 0xFF00) |
									 ((bytes[7] << 0) & 0xFF);
	header.nscount = ((bytes[8] << 8) & 0xFF00) |
									 ((bytes[9] << 0) & 0xFF);
	header.arcount = ((bytes[10] << 8) & 0xFF00) |
									 ((bytes[11] << 0) & 0xFF);

	int offset = 12;
	int tmp;

	QUESTION question;
	for (int i = 0; i < header.qdcount; i++)
	{
		question = dns_packet->question[i];
		tmp = offset;
		while (bytes[offset] != '\0')
		{
			question.qname[offset - tmp] = bytes[offset];
			offset++;
		}
		question.qname[offset - tmp] = '\0';

		question.qtype = ((bytes[offset++] << 8) & 0xFF00) |
										 ((bytes[offset++] << 0) & 0xFF);
		question.qclass = ((bytes[offset++] << 8) & 0xFF00) |
											((bytes[offset++] << 0) & 0xFF);
	}

	RR answer;
	for (int i = 0; i < header.ancount; i++)
	{
		answer = dns_packet->answer[i];
		tmp = offset;
		while (bytes[offset] != '\0')
		{
			answer.name[offset - tmp] = bytes[offset];
			offset++;
		}
		answer.name[offset - tmp] = '\0';

		answer.type = ((bytes[offset++] << 8) & 0xFF00) |
									((bytes[offset++] << 0) & 0xFF);
		answer.rclass = ((bytes[offset++] << 8) & 0xFF00) |
										((bytes[offset++] << 0) & 0xFF);
		answer.ttl = ((bytes[offset++] << 24) & 0xFF000000) |
								 ((bytes[offset++] << 16) & 0xFF0000) |
								 ((bytes[offset++] << 8) & 0xFF00) |
								 ((bytes[offset++] << 0) & 0xFF);
		answer.rdlength = ((bytes[offset++] << 8) & 0xFF00) |
											((bytes[offset++] << 0) & 0xFF);

		memcpy(answer.rdata, bytes + offset, answer.rdlength);
		offset += answer.rdlength;
	}

	RR authority;
	for (int i = 0; i < header.nscount; i++)
	{
		authority = dns_packet->authority[i];
		tmp = offset;
		while (bytes[offset] != '\0')
		{
			authority.name[offset - tmp] = bytes[offset];
			offset++;
		}
		authority.name[offset - tmp] = '\0';

		authority.type = ((bytes[offset++] << 8) & 0xFF00) |
										 (bytes[offset++] & 0xFF);
		authority.rclass = ((bytes[offset++] << 8) & 0xFF00) |
											 (bytes[offset++] & 0xFF);
		authority.ttl = ((bytes[offset++] << 24) & 0xFF000000) |
										((bytes[offset++] << 16) & 0xFF0000) |
										((bytes[offset++] << 8) & 0xFF00) |
										(bytes[offset++] & 0xFF);
		authority.rdlength = ((bytes[offset++] << 8) & 0xFF00) |
												 (bytes[offset++] & 0xFF);

		memcpy(authority.rdata, bytes + offset, authority.rdlength);
		offset += authority.rdlength;
	}

	// additional
	RR additional;
	for (int i = 0; i < header.arcount; i++)
	{
		additional = dns_packet->additional[i];
		tmp = offset;
		while (bytes[offset] != '\0')
		{
			additional.name[offset - tmp] = bytes[offset];
			offset++;
		}
		additional.name[offset - tmp] = '\0';

		additional.type = ((bytes[offset++] << 8) & 0xFF00) |
											((bytes[offset++] << 0) & 0xFF);
		additional.rclass = ((bytes[offset++] << 8) & 0xFF00) |
												((bytes[offset++] << 0) & 0xFF);
		additional.ttl = ((bytes[offset++] << 24) & 0xFF000000) |
										 ((bytes[offset++] << 16) & 0xFF0000) |
										 ((bytes[offset++] << 8) & 0xFF00) |
										 ((bytes[offset++] << 0) & 0xFF);
		additional.rdlength = ((bytes[offset++] << 8) & 0xFF00) |
													((bytes[offset++] << 0) & 0xFF);

		memcpy(additional.rdata, bytes + offset, additional.rdlength);
		offset += additional.rdlength;
	}
	return offset;
}