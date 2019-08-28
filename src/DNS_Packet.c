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


void print(DNS_PACKET dns_packet)
{
    printf("\n");
    
    printf("header.id:                  %d %d\n",  (dns_packet.header.id           >> 8) && 0xFF, 
                                                   (dns_packet.header.id           >> 0) && 0xFF);
    printf("header.qr:                  %d\n",     (dns_packet.header.qr           >> 0) && 0xFF);
    printf("header.opcode:              %d\n",     (dns_packet.header.opcode       >> 0) && 0xFF);
    printf("header.aa:                  %d\n",     (dns_packet.header.aa           >> 0) && 0xFF);
    printf("header.tc:                  %d\n",     (dns_packet.header.tc           >> 0) && 0xFF);
    printf("header.rd:                  %d\n",     (dns_packet.header.rd           >> 0) && 0xFF);
    printf("header.ra:                  %d\n",     (dns_packet.header.ra           >> 0) && 0xFF);
    printf("header.z:                   %d\n",     (dns_packet.header.z            >> 0) && 0xFF);
    printf("header.rcode:               %d\n",     (dns_packet.header.rcode        >> 0) && 0xFF);    
    printf("header.qdcount:             %d %d\n",  (dns_packet.header.qdcount      >> 8) && 0xFF, 
                                                   (dns_packet.header.qdcount      >> 0) && 0xFF);
    printf("header.ancount:             %d %d\n",  (dns_packet.header.ancount      >> 8) && 0xFF, 
                                                   (dns_packet.header.ancount      >> 0) && 0xFF);
    printf("header.nscount:             %d %d\n",  (dns_packet.header.nscount      >> 8) && 0xFF, 
                                                   (dns_packet.header.nscount      >> 0) && 0xFF);
    printf("header.arcount:             %d %d\n",  (dns_packet.header.arcount      >> 8) && 0xFF, 
                                                   (dns_packet.header.arcount      >> 0) && 0xFF);
    
    for (int i=0; i<dns_packet.header.qdcount; i++)
    {
        printf("***Question %d***\n", i);
        printf("question->qname:            ");
        for (int j=0; j<255; j++)
            printf("%d ", dns_packet.question->qname[j]);
        printf("\n");

        printf("question->qtype:            %d\n", (dns_packet.question->qtype     >> 0) && 0xFF);
        printf("question->qclass:           %d\n", (dns_packet.question->qclass    >> 0) && 0xFF);
    }
    
    for (int i=0; i<dns_packet.header.ancount; i++)
    {
        printf("***Answer %d***\n", i);
        printf("answer->name:               ");
        for (int j=0; j<255; j++)
            printf("%d ", dns_packet.answer->name[j]);
        printf("\n");

        printf("answer->type:               %d\n", (dns_packet.answer->type        >> 0) && 0xFF);
        printf("answer->rclass:             %d\n", (dns_packet.answer->rclass      >> 0) && 0xFF);    
        printf("answer->ttl:                %d\n", (dns_packet.answer->ttl         >> 0) && 0xFF);
        printf("answer->rdlength:           %d\n", (dns_packet.answer->rdlength    >> 0) && 0xFF);
        
        printf("answer->rdata:              ");
        for (int j=0; j<dns_packet.answer->rdata[0]; j++)
            printf("%d ", dns_packet.answer->rdata[j]);
        printf("\n");
    }

    for (int i=0; i<dns_packet.header.nscount; i++)
    {
        printf("***Authority %d***\n", i);
        printf("authority->name:      ");
        for (int j=0; j<255; j++)
            printf("%d ", dns_packet.authority->name[j]);
        printf("\n");

        printf("authority->type:            %d\n", (dns_packet.authority->type     >> 0) && 0xFF);
        printf("authority->rclass:          %d\n", (dns_packet.authority->rclass   >> 0) && 0xFF);    
        printf("authority->ttl:             %d\n", (dns_packet.authority->ttl      >> 0) && 0xFF);
        printf("authority->rdlength:        %d\n", (dns_packet.authority->rdlength >> 0) && 0xFF);
        
        printf("authority->rdata:           ");
        for (int j=0; j<dns_packet.authority->rdlength; j++)
            printf("%d ", dns_packet.authority->rdata[j]);
        printf("\n");
    }

    for (int i=0; i<dns_packet.header.arcount; i++)
    {
        printf("additional->name:            ");
        for (int j=0; j<255; j++)
            printf("%d ", dns_packet.additional->name[j]);
        printf("\n");

        printf("additional->type:           %d\n", (dns_packet.additional->type     >> 0) && 0xFF);
        printf("additional->rclass:         %d\n", (dns_packet.additional->rclass   >> 0) && 0xFF);    
        printf("additional->ttl:            %d\n", (dns_packet.additional->ttl      >> 0) && 0xFF);
        printf("additional->rdlength:       %d\n", (dns_packet.additional->rdlength >> 0) && 0xFF);
        
        printf("additional->rdata:          ");
        for (int j=0; j<dns_packet.additional->rdlength; j++)
            printf("%d ", dns_packet.additional->rdata[j]);
        printf("\n");
    }
    printf("\n");
}


/*
 * Perform a DNS query by sending a packet combining msg and hostname
 *
void DNS_Query (int nature, void* sockfd_void, char *msg, int len_msg, 
                char *host, char *ip_dns_server, int query_type)
{
    struct DNS_PACKET *dns_packet = malloc(sizeof(struct DNS_PACKET));
    dns_packet->header            = malloc(sizeof(struct HEADER));
    dns_packet->question          = malloc(sizeof(struct QUESTION));
    dns_packet->question->qname   = malloc(255);
    dns_packet->answer            = malloc(sizeof(struct ANSWER));
    dns_packet->answer->name      = malloc(sizeof(unsigned char)*2);
    dns_packet->answer->resource  = malloc(sizeof(struct R_DATA));
    dns_packet->answer->rdata     = malloc(sizeof(unsigned char)*2);

    int s = *(int *) sockfd_void;

    struct sockaddr_in dest;
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(5000); //DNS uses the port 53
    dest.sin_addr.s_addr = inet_addr(ip_dns_server);

    // DNS_HEADER
    struct DNS_HEADER* header = dns_packet->header;
    
    header->id = (unsigned short) htons(getpid());
    header->qr = 0; //This is a query
    header->opcode = 0; //This is a standard query
    header->aa = 0; //Not Authoritative
    header->tc = 0; //This message is not truncated
    header->rd = 1; //Recursion Desired
    header->ra = 0; //Recursion not available! hey we dont have it (lol)
    header->z = 0;
    header->ad = 0;
    header->cd = 0;
    header->rcode = 0;
    header->q_count = htons(1); //we have only 1 question
    header->ans_count = 0;
    header->auth_count = 0;
    header->add_count = 0;

    // Query portion

    // convert msg into 'd/r'+${msg}+'.'+${hostname} see DNS_Encode.c
    unsigned char msg_encoded[MAX_SZ];
    memset(msg_encoded, 0, MAX_SZ);
    unsigned char split[MAX_SZ];
    memset(split, 0, MAX_SZ);
    int len_split = DNS_Split(split, msg, len_msg);

    printf("Msg ready to send:\n");
    if (nature) //real query containing information 
    {msg_encoded[0] = 'd';}
    else //fake query requesting answers
    {msg_encoded[0] = 'r';}

    printf("%c ", msg_encoded[0]);

    for (int i=0; i<len_split; i++)
    {
        msg_encoded[i+1] = split[i];
        if (split[i] == '.'){
            printf(". ");
        }
        else {
            printf("%d ", split[i]);
        }
    }
    msg_encoded[len_split+1] = '.';
    printf(". ");
    
    for (int i=0; i<strlen(host); i++)
    {
        msg_encoded[i+len_split+2] = host[i];
        if (host[i] == '.'){
            printf(". ");
        }
        else {
            printf("%d ", host[i]);
        }
    }
    printf("\n");

    // see DNS_Encode.c
    unsigned char qname[MAX_SZ];
    memset(qname, 0, MAX_SZ);
    int len_qname = 4 + ChangetoDnsNameFormat(qname+4, msg_encoded, len_split+2+strlen(host)); //e.g. text: www.google.com & qname: 3www6google3com
    
    qname[0] = (len_qname >> 8) & 0xFF;
    qname[1] = len_qname & 0xFF;
    qname[2] = ((len_split+6) >> 8) & 0xFF;
    qname[3] = (len_split+6) & 0xFF;

    dns_packet->question->qname = (char*) qname;
    dns_packet->question->qtype = htons(query_type); //type of the query, A, MX, CNAME, NS etc
    dns_packet->question->qclass = htons(1); //its internet (lol)
    
    // Record portion
    dns_packet->record->name[0] = 0;
    dns_packet->record->name[1] = 2;
    dns_packet->record->rdata[0] = 0;
    dns_packet->record->rdata[1] = 2; 

    // print the dns_packet we just built
    
    print(dns_packet);

    char buf[MAX_SZ];
    int nb_octet_sent = Binary_from_DNS(dns_packet, buf);

    free(dns_packet->record->name);
    free(dns_packet->record->resource);
    free(dns_packet->record->rdata);
    free(dns_packet->record);
    free(header);
    //free(dns_packet->question->qname);
    free(dns_packet->question);
    free(dns_packet);

    if (nature)
    {
        printf("Sending Packet... (%d bytes)\n", nb_octet_sent);    
    }
    else
    {
        printf("Sending request for data... (%d bytes)\n", nb_octet_sent);
    }
    
    if (sendto(s, (char*)buf, nb_octet_sent, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0)
    {
        perror("Sendto failed.");
    }
    printf("Done.\n\n");
}
*/


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