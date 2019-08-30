#include <stdio.h>  //printf
#include <string.h> //strlen
#include <stdlib.h> //malloc

#include "DNS_Packet.h"
#include "DNS_Encode.h"

int qname_to_bytes(unsigned char *msg, unsigned char *qname) 
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


int DNS_to_bytes(unsigned char *bytes, DNS_PACKET dns_packet)
{
	// header
	int offset = 0;
	{
		bytes[ 0+offset] = ((dns_packet.header.id          >>  8) & 0xFF);
		bytes[ 1+offset] = ((dns_packet.header.id          >>  0) & 0xFF);
		bytes[ 2+offset] = ((dns_packet.header.qr          <<  7) & 0x80)|
						   ((dns_packet.header.opcode      <<  3) & 0x78)|
						   ((dns_packet.header.aa          <<  2) & 0x04)|
						   ((dns_packet.header.tc          <<  1) & 0x02)|
						   ((dns_packet.header.rd 	 	   <<  0) & 0x01);
		bytes[ 3+offset] = ((dns_packet.header.ra          <<  7) & 0x80)|
						   ((dns_packet.header.z           <<  4) & 0x70)|
						   ((dns_packet.header.rcode       <<  0) & 0x0F);
		bytes[ 4+offset] = ((dns_packet.header.qdcount     >>  8) & 0xFF);
		bytes[ 5+offset] = ((dns_packet.header.qdcount     >>  0) & 0xFF);
		bytes[ 6+offset] = ((dns_packet.header.ancount     >>  8) & 0xFF);
		bytes[ 7+offset] = ((dns_packet.header.ancount     >>  0) & 0xFF);
		bytes[ 8+offset] = ((dns_packet.header.nscount     >>  8) & 0xFF);
		bytes[ 9+offset] = ((dns_packet.header.nscount     >>  0) & 0xFF);
		bytes[10+offset] = ((dns_packet.header.arcount     >>  8) & 0xFF);
		bytes[11+offset] = ((dns_packet.header.arcount     >>  0) & 0xFF);
	}
    
    // question
    for (int i=0; i<dns_packet.header.qdcount; i++)
    {
    	offset += qname_to_bytes(bytes+12, dns_packet.question[i].qname);
    
		bytes[12+offset] = ((dns_packet.question[i].qtype  >>  8) & 0xFF);
		bytes[13+offset] = ((dns_packet.question[i].qtype  >>  0) & 0xFF);
		bytes[14+offset] = ((dns_packet.question[i].qclass >>  8) & 0xFF);
		bytes[15+offset] = ((dns_packet.question[i].qclass >>  0) & 0xFF);

		offset += 4;
    }

	// answer
	for (int i=0; i<dns_packet.header.ancount; i++)
	{
		offset += qname_to_bytes(bytes+16+offset, dns_packet.answer[i].name);

		bytes[16+offset] = ((dns_packet.answer[i].type 	   >>  8) & 0xFF);
		bytes[17+offset] = ((dns_packet.answer[i].type 	   >>  0) & 0xFF);
		bytes[18+offset] = ((dns_packet.answer[i].rclass   >>  8) & 0xFF);
		bytes[19+offset] = ((dns_packet.answer[i].rclass   >>  0) & 0xFF);
		bytes[20+offset] = ((dns_packet.answer[i].ttl 	   >> 24) & 0xFF);
		bytes[21+offset] = ((dns_packet.answer[i].ttl	   >> 16) & 0xFF);
		bytes[22+offset] = ((dns_packet.answer[i].ttl 	   >>  8) & 0xFF);
		bytes[23+offset] = ((dns_packet.answer[i].ttl 	   >>  0) & 0xFF);
		bytes[24+offset] = ((dns_packet.answer[i].rdlength >>  8) & 0xFF);
		bytes[25+offset] = ((dns_packet.answer[i].rdlength >>  0) & 0xFF);
		
		memcpy(bytes+26+offset, dns_packet.additional[i].rdata, 
								dns_packet.additional[i].rdlength);

		offset += 11 + dns_packet.answer[i].rdlength;
	}

	// authority
	for (int i=0; i<dns_packet.header.nscount; i++)
	{
		offset += qname_to_bytes(bytes+16+offset, dns_packet.authority[i].name);

		bytes[16+offset] = ((dns_packet.authority[i].type 	  >>  8) & 0xFF);
		bytes[17+offset] = ((dns_packet.authority[i].type 	  >>  0) & 0xFF);
		bytes[18+offset] = ((dns_packet.authority[i].rclass   >>  8) & 0xFF);
		bytes[19+offset] = ((dns_packet.authority[i].rclass   >>  0) & 0xFF);
		bytes[20+offset] = ((dns_packet.authority[i].ttl 	  >> 24) & 0xFF);
		bytes[21+offset] = ((dns_packet.authority[i].ttl	  >> 16) & 0xFF);
		bytes[22+offset] = ((dns_packet.authority[i].ttl 	  >>  8) & 0xFF);
		bytes[23+offset] = ((dns_packet.authority[i].ttl 	  >>  0) & 0xFF);
		bytes[24+offset] = ((dns_packet.authority[i].rdlength >>  8) & 0xFF);
		bytes[25+offset] = ((dns_packet.authority[i].rdlength >>  0) & 0xFF);
		
		memcpy(bytes+26+offset, dns_packet.additional[i].rdata, 
								dns_packet.additional[i].rdlength);

		offset += 11 + dns_packet.authority[i].rdlength;
	}

	// additional
	for (int i=0; i<dns_packet.header.arcount; i++)
	{
		offset += qname_to_bytes(bytes+16+offset, dns_packet.additional[i].name);

		bytes[16+offset] = ((dns_packet.additional[i].type 	   >>  8) & 0xFF);
		bytes[17+offset] = ((dns_packet.additional[i].type 	   >>  0) & 0xFF);
		bytes[18+offset] = ((dns_packet.additional[i].rclass   >>  8) & 0xFF);
		bytes[19+offset] = ((dns_packet.additional[i].rclass   >>  0) & 0xFF);
		bytes[20+offset] = ((dns_packet.additional[i].ttl 	   >> 24) & 0xFF);
		bytes[21+offset] = ((dns_packet.additional[i].ttl	   >> 16) & 0xFF);
		bytes[22+offset] = ((dns_packet.additional[i].ttl 	   >>  8) & 0xFF);
		bytes[23+offset] = ((dns_packet.additional[i].ttl 	   >>  0) & 0xFF);
		bytes[24+offset] = ((dns_packet.additional[i].rdlength >>  8) & 0xFF);
		bytes[25+offset] = ((dns_packet.additional[i].rdlength >>  0) & 0xFF);
		
		memcpy(bytes+26+offset, dns_packet.additional[i].rdata, 
								dns_packet.additional[i].rdlength);

		offset += 11 + dns_packet.additional[i].rdlength;
	}

	return 26 + offset;
}


int bytes_to_DNS(DNS_PACKET dns_packet, unsigned char *bytes)
{
   	// header
    dns_packet.header.id 	  =	((bytes[ 0] << 8) & 0xFF00)| 
    							((bytes[ 1] << 0) & 0xFF  );
    dns_packet.header.qr 	  =	((bytes[ 2] >> 7) & 0x01  );
    dns_packet.header.opcode  =	((bytes[ 2] >> 3) & 0x80  );
    dns_packet.header.aa 	  =	((bytes[ 2] >> 2) & 0x01  );
    dns_packet.header.tc 	  =	((bytes[ 2] >> 1) & 0x01  );
    dns_packet.header.rd 	  = ((bytes[ 2] >> 0) & 0x01  );
    dns_packet.header.ra 	  =	((bytes[ 3] >> 7) & 0x01  );
    dns_packet.header.z		  =	((bytes[ 3] >> 4) & 0x08  );
    dns_packet.header.rcode	  =	((bytes[ 3] >> 0) & 0x0F  );
    dns_packet.header.qdcount =	((bytes[ 4] << 8) & 0xFF00)| 
    							((bytes[ 5] << 0) & 0xFF  );
    dns_packet.header.ancount = ((bytes[ 6] << 8) & 0xFF00)| 
    							((bytes[ 7] << 0) & 0xFF  );
    dns_packet.header.nscount = ((bytes[ 8] << 8) & 0xFF00)| 
    							((bytes[ 9] << 0) & 0xFF  );
    dns_packet.header.arcount = ((bytes[10] << 8) & 0xFF00)| 
    							((bytes[11] << 0) & 0xFF  );
    
    int offset = 0;
    
    // question
   	for (int i=0; i<dns_packet.header.qdcount; i++)
   	{
		while (bytes[12+offset] != '\0')
		{
			dns_packet.question[i].qname[offset] = bytes[12+offset];
			offset++;
		}
		dns_packet.question[i].qname[offset] = '\0';

		dns_packet.question[i].qtype  =	((bytes[13+offset] << 8) & 0xFF00)|
										((bytes[14+offset] << 0) & 0xFF  );
		dns_packet.question[i].qclass =	((bytes[15+offset] << 8) & 0xFF00)|
										((bytes[16+offset] << 0) & 0xFF  );
		offset += 5;
   	}

    // answer
    for (int i=0; i<dns_packet.header.ancount; i++)
    {
		int offset0 = offset;

		while (bytes[17+offset] != '\0')
		{
			dns_packet.answer[i].name[offset-offset0] = bytes[17+offset];
			offset++;
		}
		dns_packet.answer[i].name[offset-offset0] = '\0';
		 
		dns_packet.answer[i].type     =	((bytes[18+offset] <<  8) & 0xFF00    )| 
									  	((bytes[19+offset] <<  0) & 0xFF  	  );
		dns_packet.answer[i].rclass   =	((bytes[20+offset] <<  8) & 0xFF00 	  )|
									  	((bytes[21+offset] <<  0) & 0xFF      );
		dns_packet.answer[i].ttl	  =	((bytes[22+offset] << 24) & 0xFF000000)| 
								   	  	((bytes[23+offset] << 16) & 0xFF0000  )|
								   	  	((bytes[24+offset] <<  8) & 0xFF00    )|
								   	  	((bytes[25+offset] <<  0) & 0xFF      );
		dns_packet.answer[i].rdlength = ((bytes[26+offset] <<  8) & 0xFF00    )| 
										((bytes[27+offset] <<  0) & 0xFF      );

		memcpy(dns_packet.answer[i].rdata, bytes+28+offset, dns_packet.answer[i].rdlength);

		offset += 12 + dns_packet.answer[i].rdlength;
	}

	// authority
    for (int i=0; i<dns_packet.header.nscount; i++)
    {
		int offset0 = offset;

		while (bytes[17+offset] != '\0')
		{
			dns_packet.authority[i].name[offset-offset0] = bytes[17+offset];
			offset++;
		}
		dns_packet.authority[i].name[offset-offset0] = '\0';
		 
		dns_packet.authority[i].type     = ((bytes[18+offset] <<  8) & 0xFF00    )| 
									  	   ((bytes[19+offset] <<  0) & 0xFF  	 );
		dns_packet.authority[i].rclass   = ((bytes[20+offset] <<  8) & 0xFF00 	 )|
									  	   ((bytes[21+offset] <<  0) & 0xFF      );
		dns_packet.authority[i].ttl	     = ((bytes[22+offset] << 24) & 0xFF000000)| 
								   	  	   ((bytes[23+offset] << 16) & 0xFF0000  )|
								   	  	   ((bytes[24+offset] <<  8) & 0xFF00    )|
								   	  	   ((bytes[25+offset] <<  0) & 0xFF      );
		dns_packet.authority[i].rdlength = ((bytes[26+offset] <<  8) & 0xFF00    )| 
										   ((bytes[27+offset] <<  0) & 0xFF      );

		memcpy(dns_packet.authority[i].rdata, bytes+28+offset, dns_packet.authority[i].rdlength);

		offset += 12 + dns_packet.authority[i].rdlength;
	}

	// additional
    for (int i=0; i<dns_packet.header.arcount; i++)
    {
		int offset0 = offset;

		while (bytes[17+offset] != '\0')
		{
			dns_packet.additional[i].name[offset-offset0] = bytes[17+offset];
			offset++;
		}
		dns_packet.additional[i].name[offset-offset0] = '\0';
		 
		dns_packet.additional[i].type     =	((bytes[18+offset] <<  8) & 0xFF00    )| 
									  		((bytes[19+offset] <<  0) & 0xFF  	  );
		dns_packet.additional[i].rclass   =	((bytes[20+offset] <<  8) & 0xFF00 	  )|
									  		((bytes[21+offset] <<  0) & 0xFF      );
		dns_packet.additional[i].ttl	  =	((bytes[22+offset] << 24) & 0xFF000000)| 
								   	  		((bytes[23+offset] << 16) & 0xFF0000  )|
								   	  		((bytes[24+offset] <<  8) & 0xFF00    )|
								   	  		((bytes[25+offset] <<  0) & 0xFF      );
		dns_packet.additional[i].rdlength = ((bytes[26+offset] <<  8) & 0xFF00    )| 
											((bytes[27+offset] <<  0) & 0xFF      );

		memcpy(dns_packet.additional[i].rdata, bytes+28+offset, dns_packet.additional[i].rdlength);

		offset += 12 + dns_packet.additional[i].rdlength;
	}

	return 17+offset;
}


// testing purposes
int main(int argc, char* argv[])
{
    int len_msg = 1024;
    unsigned char msg[len_msg];

    for (int i=0; i<len_msg-1; i++)
    	msg[i] = 1;
    msg[len_msg-1] = '\0';

	/*
	printf("Enter the msg to encode: ");
	fgets(msg, 1024, stdin);

	// Remove trailing newline, if there is.
	if ((strlen(msg) > 0) && (msg[strlen(msg)-1] == '\n'))
		msg[strlen(msg)-1] = '\0';
	*/

	printf("Original = (1024 bytes)\n");

	for (int i=0; i<len_msg; i++)
		printf("%d", msg[i]);
	printf("\n\n");
	
	/*
	unsigned char *qnames[len_msg/250+1]; 

	for (int i=0; i<len_msg/250+1; i++)
		qnames[i] = malloc(255);
	*/

	
	DNS_PACKET dns_packets[len_msg/250+1]; 

	for (int i=0; i<len_msg/250+1; i++)
	{
		dns_packets[i].question = malloc(sizeof(dns_packets[i].question));
		dns_packets[i].question->qname = malloc(255);
	}

	int nb_packets = msg_to_DNSs(dns_packets, msg, len_msg); 

	printf("Encoded = (%d packets)\n", nb_packets);
	
	for (int i=0; i<nb_packets; i++)
	{
		print(dns_packets[i]);
		free(dns_packets[i].question->qname);
		free(dns_packets[i].question);
	}
	/*
	info_qnames info = msg_to_qnames(qnames, msg, 1024); 

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

	for (int i=0; i<len_msg/250+1; i++)
		free(qnames[i]);
	
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
	*/
	return 0;
}












