/*
 * Modified from :
 * https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
 * which orginally performs a DNS Query from input hostname
 * 
 * Author : Silver Moon (m00n.silv3r@gmail.com)
 * Dated : 29/4/2009
 * */

#include <stdio.h>      //printf
#include <string.h>     //strlen
#include <stdlib.h>     //malloc
#include <sys/socket.h> //sockets
#include <arpa/inet.h>  //inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <unistd.h>     //getpid

#include "DNS_Packet.h"
#include "DNS_Encode.h"
#include "DNS_flag.h"


void print_DNS(DNS_PACKET dns_packet)
{
    printf("\n***************\n");
    printf("*  DNS Start  *\n");
    printf("***************\n");
    printf("\n** Header **\n");
    printf("header.id:                  %02x %02x\n", (dns_packet.header.id           >> 8) && 0xFF, 
                                                      (dns_packet.header.id           >> 0) && 0xFF);
    printf("header.qr:                  %02x\n",      (dns_packet.header.qr           >> 0) && 0xFF);
    printf("header.opcode:              %02x\n",      (dns_packet.header.opcode       >> 0) && 0xFF);
    printf("header.aa:                  %02x\n",      (dns_packet.header.aa           >> 0) && 0xFF);
    printf("header.tc:                  %02x\n",      (dns_packet.header.tc           >> 0) && 0xFF);
    printf("header.rd:                  %02x\n",      (dns_packet.header.rd           >> 0) && 0xFF);
    printf("header.ra:                  %02x\n",      (dns_packet.header.ra           >> 0) && 0xFF);
    printf("header.z:                   %02x\n",      (dns_packet.header.z            >> 0) && 0xFF);
    printf("header.rcode:               %02x\n",      (dns_packet.header.rcode        >> 0) && 0xFF);    
    printf("header.qdcount:             %02x %02x\n", (dns_packet.header.qdcount      >> 8) && 0xFF, 
                                                      (dns_packet.header.qdcount      >> 0) && 0xFF);
    printf("header.ancount:             %02x %02x\n", (dns_packet.header.ancount      >> 8) && 0xFF, 
                                                      (dns_packet.header.ancount      >> 0) && 0xFF);
    printf("header.nscount:             %02x %02x\n", (dns_packet.header.nscount      >> 8) && 0xFF, 
                                                      (dns_packet.header.nscount      >> 0) && 0xFF);
    printf("header.arcount:             %02x %02x\n", (dns_packet.header.arcount      >> 8) && 0xFF, 
                                                      (dns_packet.header.arcount      >> 0) && 0xFF);
    
    for (int i=0; i<dns_packet.header.qdcount; i++)
    {
        printf("\n** Question %d **\n", i);
        printf("question->qname:            ");
        for (int j=0; j<255; j++)
            printf("%02x ", dns_packet.question->qname[j]);
        printf("\n");

        printf("question->qtype:            %02x\n", (dns_packet.question->qtype     >> 0) && 0xFF);
        printf("question->qclass:           %02x\n", (dns_packet.question->qclass    >> 0) && 0xFF);
    }
    
    for (int i=0; i<dns_packet.header.ancount; i++)
    {
        printf("\n** Answer %d **\n", i);
        printf("answer->name:               ");
        for (int j=0; j<255; j++)
            printf("%02x ", dns_packet.answer->name[j]);
        printf("\n");

        printf("answer->type:               %02x\n", (dns_packet.answer->type        >> 0) && 0xFF);
        printf("answer->rclass:             %02x\n", (dns_packet.answer->rclass      >> 0) && 0xFF);    
        printf("answer->ttl:                %02x\n", (dns_packet.answer->ttl         >> 0) && 0xFF);
        printf("answer->rdlength:           %02x\n", (dns_packet.answer->rdlength    >> 0) && 0xFF);
        
        printf("answer->rdata:              ");
        for (int j=0; j<dns_packet.answer->rdata[0]; j++)
            printf("%02x ", dns_packet.answer->rdata[j]);
        printf("\n");
    }

    for (int i=0; i<dns_packet.header.nscount; i++)
    {
        printf("\n** Authority %d **\n", i);
        printf("authority->name:      ");
        for (int j=0; j<255; j++)
            printf("%d ", dns_packet.authority->name[j]);
        printf("\n");

        printf("authority->type:            %02x\n", (dns_packet.authority->type     >> 0) && 0xFF);
        printf("authority->rclass:          %02x\n", (dns_packet.authority->rclass   >> 0) && 0xFF);    
        printf("authority->ttl:             %02x\n", (dns_packet.authority->ttl      >> 0) && 0xFF);
        printf("authority->rdlength:        %02x\n", (dns_packet.authority->rdlength >> 0) && 0xFF);
        
        printf("authority->rdata:           ");
        for (int j=0; j<dns_packet.authority->rdlength; j++)
            printf("%02x ", dns_packet.authority->rdata[j]);
        printf("\n");
    }

    for (int i=0; i<dns_packet.header.arcount; i++)
    {
        printf("additional->name:            ");
        for (int j=0; j<255; j++)
            printf("%02x ", dns_packet.additional->name[j]);
        printf("\n");

        printf("additional->type:           %02x\n", (dns_packet.additional->type     >> 0) && 0xFF);
        printf("additional->rclass:         %02x\n", (dns_packet.additional->rclass   >> 0) && 0xFF);    
        printf("additional->ttl:            %02x\n", (dns_packet.additional->ttl      >> 0) && 0xFF);
        printf("additional->rdlength:       %02x\n", (dns_packet.additional->rdlength >> 0) && 0xFF);
        
        printf("additional->rdata:          ");
        for (int j=0; j<dns_packet.additional->rdlength; j++)
            printf("%02x ", dns_packet.additional->rdata[j]);
        printf("\n");
    }
    printf("\n*************\n");
    printf("*  DNS End  *\n");
    printf("*************\n");
}


void print_bytes(unsigned char *bytes, int len_bytes)
{
    printf("\n");
    for (int i=0; i<len_bytes; i++)
        printf("%02x ", bytes[i]);
    printf("(%d bytes)\n", len_bytes);
}

/*
 * Get the DNS servers from /etc/resolv.conf file on Linux

void get_dns_servers()
{
    FILE *fp;
    char line[200] , *p;
    if((fp = fopen("/etc/resolv.conf" , "r")) == NULL)
    {
        printf("Failed opening /etc/resolv.conf file \n");
    }
     
    while(fgets(line , 200 , fp))
    {
        if(line[0] == '#')
        {
            continue;
        }
        if(strncmp(line , "nameserver" , 10) == 0)
        {
            p = strtok(line , " ");
            p = strtok(NULL , " ");
             
            //p now is the dns ip :)
            //????
        }
    }
     
    strcpy(dns_servers[0] , "208.67.222.222");
    strcpy(dns_servers[1] , "208.67.220.220");
}
*/