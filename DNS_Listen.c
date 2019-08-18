/*Listen from the DNS_Server after sending messages*/

/*
Modified from :
https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
which orginally performs a DNS Query from input hostname

Author : Silver Moon (m00n.silv3r@gmail.com)
Dated : 29/4/2009
*/

//Header Files
#include <stdio.h> //printf
#include <string.h> //strlen
#include <stdlib.h> //malloc
#include <sys/socket.h> //you know what this is for
#include <arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <unistd.h> //getpid

#include "DNS_Query.h"
#include "DNS_Listen.h"
#include "DNS_Decode.h"

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
#define T_TXT 16

#define MAX_SZ 32768

char* Listen(void* sockfd_void, char *ip_dns_server)
	{	
		char buf[MAX_SZ*2];
		memset(buf, 0, MAX_SZ*2);

	    int sockfd = *(int *) sockfd_void;
	    struct sockaddr_in a;

	    struct DNS_PACKET *dnspacket = NULL;

	    /* DNS server parameters */
	    struct sockaddr_in dest;
	    dest.sin_family = AF_INET;
	    dest.sin_port = htons(5000); //DNS uses the port 53
	    dest.sin_addr.s_addr = inet_addr(ip_dns_server);
	    
	    /* Receiving answer */
	    int c = sizeof(dest);
	    int nb_octet_received = recvfrom(sockfd, buf, MAX_SZ, 0, (struct sockaddr*)&dest, (socklen_t*) &c);
	    if (nb_octet_received <= 0)
	    {
	        perror("Recvfrom");
	    }
	    
	    printf("Received %d bytes.\n", nb_octet_received);
	    buf[nb_octet_received]='\0';

	    printf("\n******************Begin: Received DNS Packet information*******************\n");
	    
	    char newresu[32768];
	    memcpy(newresu, buf, 32768);
	    
	    /*
	    for( int a = 0; a < nb_octet_received; a = a + 1 ){
	    	if (a<34){
	    		printf("%de value of a: %d\n", a, buf[a]);
	    	}
	    	else{
	    		printf("%de value of a: %c\n", a, buf[a]);
	    	}
	    }
	    */

	    struct DNS_PACKET* response = DNS_from_Binary(newresu);

	    printf("\nheader->id: %d\n", response->header->id);
	    printf("header->rd: %d\n", response->header->rd);
	    printf("header->tc: %d\n", response->header->tc);
	    printf("header->aa: %d\n", response->header->aa);
	    printf("header->qr: %d\n", response->header->qr);
	    printf("header->opcode: %d\n", response->header->opcode);
	    printf("header->rcode: %d\n", response->header->rcode);
	    printf("header->cd: %d\n", response->header->cd);
	    printf("header->ad: %d\n", response->header->ad);
	    printf("header->z: %d\n", response->header->z);
	    printf("header->ra: %d\n",  response->header->ra);
	    printf("header->q_count: %d\n", response->header->q_count);
	    printf("header->ans_count: %d\n", response->header->ans_count);
	    printf("header->auth_count: %d\n", response->header->auth_count);
	    printf("header->add_count: %d\n", response->header->add_count);
	    
	    printf("question->qname: ");
	    int len_qname = ((unsigned char) response->question->qname[0])*256 + (unsigned char) response->question->qname[1];
	    for (int i=0; i<len_qname; i++){
        	printf("%d", response->question->qname[i]);
    	}
    	printf("\n");
	    
	    printf("question->qtype: %d\n", response->question->qtype);
	    printf("question->qclass: %d\n", response->question->qclass);
	    
	    printf("record->name: ");
	    int len_name = ((unsigned char) response->record->name[0])*256 + (unsigned char) response->record->name[1];
	    for (int i=0; i<256*response->record->name[0]+response->record->name[1]; i++){
        	printf("%d", response->record->name[i]);
    	}
    	printf("\n");
	    
	    printf("record->resource->type: %d\n", response->record->resource->type);
	    printf("record->resource->rclass: %d\n", response->record->resource->rclass);    
	    printf("record->resource->ttl: %d\n", response->record->resource->ttl);
	    printf("record->resource->data_len: %d\n", response->record->resource->data_len);
	    
	    printf("record->rdata: ");
	    int len_rdata = ((unsigned char) response->record->rdata[0])*256 + (unsigned char) response->record->rdata[1];
	    for (int i=0; i< len_rdata; i++){
        	printf("%d", response->record->rdata[i]);
    	}
    	printf("\n\n");
	    printf("*******************End: Received DNS Packet information********************\n\n");


	    
	    char* msg = (char*) malloc(len_qname);//len_rdata;
	    memcpy(msg, response->question->qname, len_qname);//response->record->rdata);

	    free(response->header);
	    free(response->question->qname);
	    free(response->question);
	    free(response->record->resource);
	    free(response->record->name);
	    free(response->record->rdata);
	    free(response->record);
	    free(response);

	    return msg;
	    
	    /*
	    printf("\nThe response contains : ");
	    printf("\n %d Questions.", ntohs((dnspacket->header)->q_count));
	    printf("\n %d Answers.", ntohs((dnspacket->header)->ans_count));
	    printf("\n %d Authoritative Servers.", ntohs((dnspacket->header)->auth_count));
	    printf("\n %d Additional records.\n\n", ntohs((dnspacket->header)->add_count));
	 
	    //Start reading answers
	    struct RES_RECORD answer;
	    struct RES_RECORD reader[sizeof(struct RES_RECORD)]; 
	    memcpy(reader, dnspacket->record, sizeof(struct RES_RECORD));
		
        answer.name = ReadName(reader->name, buf);
        answer.resource = reader->resource;
 
        if (ntohs(answer.resource->type) == 1) //if its an ipv4 address
        {
            answer.rdata = (char*) malloc(ntohs(answer.resource->data_len));
 
            for(int j=0; j<ntohs(answer.resource->data_len); j++)
            {
                answer.rdata[j]=(reader->rdata)[j];
            }
 
            answer.rdata[ntohs(answer.resource->data_len)] = '\0';
        }
        else
        {
            answer.rdata = ReadName(reader->name, buf);
        }
	 	
	 	//print answer
        printf("Name: %s ", answer.name);
         
        char* received = NULL;

        if (ntohs(answer.resource->type) == T_TXT) 
        {
            if (ntohs(answer.resource->type) == T_TXT) //Canonical name for an alias
        	{
	            char* msg = DNS_Unsplit(answer.name);
	            received = msg + 1;
	            printf("Msg received: '%s'\n", received);
        	}
        }
        else {printf("Msg received type error.\n");}
 
        printf("\n");

		free(answer.name);
		free(answer.rdata);
		free(dnspacket->question->qname);
		free(dnspacket->record->name);
		free(dnspacket->record->resource);
		free(dnspacket->record->rdata);
		free(dnspacket->header);
		free(dnspacket->question);
		free(dnspacket->record);
		free(dnspacket);

		return received;

	    //read authorities
	    for(i=0; i<ntohs(dns->auth_count); i++)
	    {
	        auth[i].name = ReadName(reader, buf, &stop);
	        reader += stop;
	 
	        auth[i].resource = (struct R_DATA*) (reader);
	        reader += sizeof(struct R_DATA);
	 
	        auth[i].rdata = ReadName(reader, buf, &stop);
	        reader += stop;
	    }
	 
	    //read additional
	    for(i=0;i<ntohs(dns->add_count);i++)
	    {
	        addit[i].name = ReadName(reader,buf,&stop);
	        reader += stop;
	 
	        addit[i].resource = (struct R_DATA*) (reader);
	        reader += sizeof(struct R_DATA);
	 
	        if (ntohs(addit[i].resource->type) == 1)
	        {
	            addit[i].rdata = (unsigned char*) malloc(ntohs(addit[i].resource->data_len));
	            for(j=0; j<ntohs(addit[i].resource->data_len); j++)
	            addit[i].rdata[j] = reader[j];
	 
	            addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
	            reader += ntohs(addit[i].resource->data_len);
	        }
	        else
	        {
	            addit[i].rdata = ReadName(reader,buf,&stop);
	            reader += stop;
	        }
	    }
	 
	    //print authorities
	    printf("\nAuthoritive Records: %d \n", ntohs(dns->auth_count) );
	    for (i = 0; i < ntohs(dns->auth_count); i++)
	    {
	        printf("Name: %s ", auth[i].name);
	        if(ntohs(auth[i].resource->type)==2)
	        {
	            printf("has nameserver : %s", auth[i].rdata);
	        }
	        printf("\n");
		free(auth[i].name);
	    }
	 
	    //print additional resource records
	    printf("\nAdditional Records : %d \n", ntohs(dns->add_count) );
	    for(i=0; i < ntohs(dns->add_count); i++)
	    {
	        printf("Name : %s ", addit[i].name);
	        if (ntohs(addit[i].resource->type) == 1)
	        {
	            long *p;
	            p = (long*) addit[i].rdata;
	            a.sin_addr.s_addr = (*p);
	            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
		    free(addit[i].rdata);
	        }
	        printf("\n");
	    }
	    */
	}
