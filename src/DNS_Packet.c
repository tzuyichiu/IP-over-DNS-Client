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

#include "DNS_Query.h"
#include "DNS_Encode.h"
#include "DNS_flag.h"


void print(DNS_PACKET dns_packet)
{
    printf("\n\n*******************Begin Sent DNS Packet information*******************\n");
    
    printf("header.id:                 %d %d\n",   dns_packet.header.id / 256, 
                                                   dns_packet.header.id % 256);
    printf("header.qr:                 %d\n",      dns_packet.header.qr);
    printf("header.opcode:             %d\n",      dns_packet.header.opcode);
    printf("header.aa:                 %d\n",      dns_packet.header.aa);
    printf("header.tc:                 %d\n",      dns_packet.header.tc);
    printf("header.rd:                 %d\n",      dns_packet.header.rd);
    printf("header.ra:                 %d\n",      dns_packet.header.ra);
    printf("header.z:                  %d\n",      dns_packet.header.z);
    printf("header.rcode:              %d\n",      dns_packet.header.rcode);    
    printf("header.qdcount:            %d %d\n",   dns_packet.header.qdcount / 256, 
                                                   dns_packet.header.qdcount % 256);
    printf("header.ancount:            %d %d\n",   dns_packet.header.ancount / 256, 
                                                   dns_packet.header.ancount % 256);
    printf("header.nscount:            %d %d\n",   dns_packet.header.nscount / 256, 
                                                   dns_packet.header.nscount % 256);
    printf("header.arcount:            %d %d\n",   dns_packet.header.arcount / 256, 
                                                   dns_packet.header.arcount % 256);
    printf("question->qname:            ")
    for (int i=0; i<sizeof(dns_packet.question->qname); i++)
        printf("%d ",                              dns_packet.question->qname[i]);
    printf("\n");

    printf("question->qtype:            %d\n",     dns_packet.question->qtype);
    printf("question->qclass:           %d\n",     dns_packet.question->qclass);
    printf("answer->name:               %d %d\n",  dns_packet.answer->name / 256,
                                                   dns_packet.answer->name % 256);
    printf("answer->resource->type:     %d\n",     dns_packet.answer->resource->type);
    printf("answer->resource->rclass:   %d\n",     dns_packet.answer->resource->rclass);    
    printf("answer->resource->ttl:      %d\n",     dns_packet.answer->resource->ttl);
    printf("answer->resource->rdlength: %d\n",     dns_packet.answer->resource->rdlength);
    
    printf("answer->rdata:              ")
    for (int i=0; i<dns_packet.answer->resource->rdlength; i++)
        printf("%d ",                              dns_packet.answer->rdata[i]);
    printf("\n");
    
    printf("********************End Sent DNS Packet information********************\n\n");
}


/*
 * Perform a DNS query by sending a packet combining msg and hostname
 * */
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

    /* see DNS_Encode.c */
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

    /* print the dns_packet we just built */
    
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

/* Careful! After usage, free memory of:
 * dns_packet->header & dns_packet->question->qname & dns_packet->question & dns_packet->record->name &
 * dns_packet->record->rdata & dns_packet->record & dns_packet
 */

struct DNS_PACKET* new_from_values(unsigned char qr, char* qname, unsigned short qtype, unsigned short qclass)
{
    struct DNS_PACKET *dns_packet = (struct DNS_PACKET*) malloc(sizeof(struct DNS_PACKET));

    struct DNS_HEADER *header = (struct DNS_HEADER*) malloc(sizeof(struct DNS_HEADER));
    struct QUESTION *question = (struct QUESTION*) malloc(sizeof(struct QUESTION));
    struct RES_RECORD *record = (struct RES_RECORD*) malloc(sizeof(struct RES_RECORD));

    dns_packet->header = header;
    dns_packet->question = question;
    dns_packet->record = record;

    header->id = 0; // à utiliser dans un futur pour traquer les numéros de requête.
    header->qr = qr; // Query: 0; Response: 1. 
    header->opcode = 0; // Standard query
    header->aa = 0; // Authoritative Answer: false, mais on s'en sert pas.
    header->tc = 0; // No truncation, a priori. 
    header->rd = 1; // Recursion desired: 1 pour l'instant.
    header->ra = 0; // Recursion available: 0.
    header->z = 0;
    header->rcode = 0;
    header->cd = 0;
    header->ad = 0;
    header->q_count = 1;
    header->ans_count = 0; // Cette valeur, ainsi que les 3 qui suivent,
                           // être complétées dans le code client. 
    header->auth_count = 0;
    header->add_count = 0;

    int len_qname = ((unsigned char) qname[0])*256 + (unsigned char) qname[1];
    dns_packet->question->qname = (char*) malloc(len_qname);
    memcpy(dns_packet->question->qname, qname, len_qname);

    question->qtype = qtype;
    question->qclass = qclass;

    dns_packet->record->name = (char*) malloc(sizeof(char)*2);
    dns_packet->record->rdata = (char*) malloc(sizeof(char)*2);

    record->rdata[0] = 0;
    record->rdata[1] = 2;
    record->name[0] = 0;
    record->name[1] = 2;


    return dns_packet;
}

/* Careful! After usage, free memory of:
 * rr->name & rr->rdata & rr
 */

struct RES_RECORD* new_from_hash(char* name, unsigned short type, unsigned short rclass, 
                                 unsigned int ttl, char* rdata)
{
    struct RES_RECORD *rr = (struct RES_RECORD*) malloc(sizeof(struct RES_RECORD));
    struct R_DATA *resource = (struct R_DATA*) malloc(sizeof(struct R_DATA));
    
    int len_name = ((unsigned char) name[0])*256 + (unsigned char) name[1];
    memcpy(rr->name, name, len_name);
    rr->resource->type = type;
    rr->resource->rclass = rclass;
    rr->resource->ttl = ttl;
    int len_rdata = ((unsigned char) rdata[0])*256 + (unsigned char) rdata[1];
    rr->resource->data_len = len_rdata;
    memcpy(rr->rdata, rdata, len_rdata);

    return rr;
}

int Binary_from_DNS(struct DNS_PACKET *dns_packet, char* resu){
    resu[0] = ((dns_packet->header->id) >> 8) & 0xFF;
    resu[1] = (dns_packet->header->id) & 0xFF;
    resu[2] = dns_packet->header->rd;
    resu[3] = dns_packet->header->tc;
    resu[4] = dns_packet->header->aa;
    resu[5] = dns_packet->header->qr;
    resu[6] = dns_packet->header->opcode;
    resu[7] = dns_packet->header->rcode;
    resu[8] = dns_packet->header->cd;
    resu[9] = dns_packet->header->ad;
    resu[10] = dns_packet->header->z;
    resu[11] = dns_packet->header->ra;
    resu[12] = ((dns_packet->header->q_count) >> 8) & 0xFF;
    resu[13] = (dns_packet->header->q_count) & 0xFF;
    resu[14] = ((dns_packet->header->ans_count) >> 8) & 0xFF;
    resu[15] = (dns_packet->header->ans_count) & 0xFF;
    resu[16] = ((dns_packet->header->auth_count) >> 8) & 0xFF;
    resu[17] = (dns_packet->header->auth_count) & 0xFF;
    resu[18] = ((dns_packet->header->add_count) >> 8) & 0xFF;
    resu[19] = (dns_packet->header->add_count) & 0xFF;
    //end header
    resu[20] = ((dns_packet->question->qtype) >> 8) & 0xFF;
    resu[21] = (dns_packet->question->qtype) & 0xFF;
    resu[22] = ((dns_packet->question->qclass) >> 8) & 0xFF;
    resu[23] = (dns_packet->question->qclass) & 0xFF;
    //end constant fields of question
    resu[24] = ((dns_packet->record->resource->type) >> 8) & 0xFF;
    resu[25] = (dns_packet->record->resource->type) & 0xFF;
    resu[26] = ((dns_packet->record->resource->rclass) >> 8) & 0xFF;
    resu[27] = (dns_packet->record->resource->rclass) & 0xFF;

    resu[28] = ((dns_packet->record->resource->ttl) >> 24) & 0xFF;
    resu[29] = ((dns_packet->record->resource->ttl) >> 16) & 0xFF;
    resu[30] = ((dns_packet->record->resource->ttl) >> 8) & 0xFF;
    resu[31] = (dns_packet->record->resource->ttl) & 0xFF;

    resu[32] = ((dns_packet->record->resource->data_len) >> 8) & 0xFF;
    resu[33] = (dns_packet->record->resource->data_len) & 0xFF;
    //end constant fields of record resource

    //Here we finish the attibutes of constant length. 
    int indice;
    char* pointer = resu;
    pointer = pointer + 34;
    int len_qname = ((unsigned char) dns_packet->question->qname[0])*256 + (unsigned char) dns_packet->question->qname[1];
    memcpy(pointer, dns_packet->question->qname, len_qname);
    //printf("%d\n", len_qname);
    pointer = pointer + len_qname;
    indice = 34 + len_qname;

    int len_rdata = ((unsigned char) dns_packet->record->rdata[0])*256 + (unsigned char) dns_packet->record->rdata[1];
    memcpy(pointer, dns_packet->record->rdata, len_rdata);
    pointer = pointer + len_rdata;
    indice = indice + len_rdata;
    
    int len_name = ((unsigned char) dns_packet->record->name[0])*256 + (unsigned char) dns_packet->record->name[1];
    memcpy(pointer, dns_packet->record->name, len_name);
    indice = indice + len_name;
    resu[indice] = '\0';
    return indice;
};

unsigned char* substring(char* str, int start, int length){
    unsigned char* resu = (unsigned char*) malloc(length);
    int i = 0;
    while (i<length){
        resu[i]=str[start+i];
        i++;
    }
    return resu;
}

/* 
 * Careful! After usage, free memory of:
 * dns_packet & dns_packet->header & dns_packet->question & dns_packet->record & dns_packet->record->resource
 */
struct DNS_PACKET* DNS_from_Binary(char* resu) // FALSE!
{
    struct DNS_PACKET *dns_packet = (struct DNS_PACKET*) malloc(sizeof(struct DNS_PACKET));
    
    dns_packet->header = (struct DNS_HEADER*) malloc(sizeof(struct DNS_HEADER));
    struct DNS_HEADER *header = dns_packet->header;
    header->id = 256*resu[0]+resu[1];
    header->rd = resu[2];
    header->tc = resu[3];
    header->aa = resu[4];
    header->qr = resu[5];
    header->opcode = resu[6];
    header->rcode = resu[7];
    header->cd = resu[8];
    header->ad = resu[9];
    header->z = resu[10];
    header->ra = resu[11];
    header->q_count = 256*resu[12]+resu[13];
    header->ans_count = 256*resu[14]+resu[15];
    header->auth_count = 256*resu[16]+resu[17];
    header->add_count = 256*resu[18]+resu[19];

    dns_packet->question = (struct QUESTION*) malloc(sizeof(struct QUESTION));
    struct QUESTION *question = dns_packet->question;
    
    question->qtype = 256*resu[20]+resu[21];
    question->qclass = 256*resu[22]+resu[23];

    dns_packet->record = (struct RES_RECORD*) malloc(sizeof(struct RES_RECORD));
    struct RES_RECORD *record = dns_packet->record;
    record->resource = (struct R_DATA*) malloc(sizeof(struct R_DATA));
    record->resource->type = 256*resu[24]+resu[25];
    record->resource->rclass = 256*resu[26]+resu[27];
    record->resource->ttl = 65536*resu[28]+4096*resu[29]+256*resu[30]+resu[31];
    record->resource->data_len = 256*resu[32]+resu[33];

    // On a fini d'affecter les champs de taille constante. 
    char* pointer = resu;
    pointer = pointer + 34;// 34: début de qname;
    int len_qname = 256* ((unsigned char) pointer[0]) + (unsigned char) pointer[1];

    question->qname = (char*) substring(resu, 34, len_qname); // 34: début de qname;

    pointer += len_qname;
    int len_rdata = 256*((unsigned char) pointer[0]) + (unsigned char) pointer[1];
    record->rdata = substring(resu, 34 + len_qname, len_rdata);

    pointer += len_rdata;

    int len_name = 256*((unsigned char) pointer[0]) + (unsigned char) pointer[1];
    record->name = substring(resu, 34 + len_qname + len_rdata, len_name); // 36+len_qname+len_rdata: 
    dns_packet->question = question;
    dns_packet->record = record;

    return dns_packet;
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