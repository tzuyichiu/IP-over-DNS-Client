//Change our message into a DNS Query

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
#include "DNS_Encode.h"


#define MAX_SZ 32768

/*
 * Perform a DNS query by sending a packet combining msg and hostname
 * */
void DNS_Query(int nature, void* sockfd_void, char *msg, int len_msg, char *host, char *ip_dns_server, int query_type)
{
    struct DNS_PACKET *dnspacket = NULL;
    dnspacket = (struct DNS_PACKET*) malloc(sizeof(struct DNS_PACKET));
    dnspacket->header = (struct DNS_HEADER*) malloc(sizeof(struct DNS_HEADER));
    dnspacket->question = (struct QUESTION*) malloc(sizeof(struct QUESTION));
    dnspacket->question->qname = (char*) malloc(MAX_SZ);
    dnspacket->record = (struct RES_RECORD*) malloc(sizeof(struct RES_RECORD));
    dnspacket->record->name = (unsigned char*) malloc(sizeof(unsigned char)*2);
    dnspacket->record->resource = (struct R_DATA*) malloc(sizeof(struct R_DATA));
    dnspacket->record->rdata = (unsigned char*) malloc(sizeof(unsigned char)*2);

    int s = *(int *) sockfd_void;

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(5000); //DNS uses the port 53
    dest.sin_addr.s_addr = inet_addr(ip_dns_server);

    // DNS_HEADER
    struct DNS_HEADER* header = NULL;
    header = dnspacket->header;
    
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

    dnspacket->question->qname = (char*) qname;
    dnspacket->question->qtype = htons(query_type); //type of the query, A, MX, CNAME, NS etc
    dnspacket->question->qclass = htons(1); //its internet (lol)
    
    // Record portion
    dnspacket->record->name[0] = 0;
    dnspacket->record->name[1] = 2;
    dnspacket->record->rdata[0] = 0;
    dnspacket->record->rdata[1] = 2; 

    /* print the dnspacket we just built */
    printf("\n\n*******************Begin Sent DNS Packet information*******************\n");
    printf("header->id: %d\n", dnspacket->header->id);
    printf("header->rd: %d\n", dnspacket->header->rd);
    printf("header->tc: %d\n", dnspacket->header->tc);
    printf("header->aa: %d\n", dnspacket->header->aa);
    printf("header->qr: %d\n", dnspacket->header->qr);
    printf("header->opcode: %d\n", dnspacket->header->opcode);
    printf("header->rcode: %d\n", dnspacket->header->rcode);
    printf("header->cd: %d\n", dnspacket->header->cd);
    printf("header->ad: %d\n", dnspacket->header->ad);
    printf("header->z: %d\n", dnspacket->header->z);
    printf("header->ra: %d\n", dnspacket->header->ra);
    printf("header->q_count: %d\n", dnspacket->header->q_count);
    printf("header->ans_count: %d\n", dnspacket->header->ans_count);
    printf("header->auth_count: %d\n", dnspacket->header->auth_count);
    printf("header->add_count: %d\n", dnspacket->header->add_count);
    printf("question->qname: ");
    for (int i = 0; i < len_qname; i++){
        printf("%d", dnspacket->question->qname[i]);
    }
    printf("\n");
    printf("question->qtype: %d\n", dnspacket->question->qtype);
    printf("question->qclass: %d\n", dnspacket->question->qclass);
    printf("record->name: 02\n");
    printf("record->resource->type: %d\n", dnspacket->record->resource->type);
    printf("record->resource->rclass: %d\n", dnspacket->record->resource->rclass);    
    printf("record->resource->ttl: %d\n", dnspacket->record->resource->ttl);
    printf("record->resource->data_len: %d\n", dnspacket->record->resource->data_len);
    printf("record->rdata: 02\n\n");
    printf("********************End Sent DNS Packet information********************\n\n");

    char buf[MAX_SZ];
    int nb_octet_sent = Binary_from_DNS(dnspacket, buf);

    free(dnspacket->record->name);
    free(dnspacket->record->resource);
    free(dnspacket->record->rdata);
    free(dnspacket->record);
    free(header);
    //free(dnspacket->question->qname);
    free(dnspacket->question);
    free(dnspacket);

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
 * dnspacket->header & dnspacket->question->qname & dnspacket->question & dnspacket->record->name &
 * dnspacket->record->rdata & dnspacket->record & dnspacket
 */

struct DNS_PACKET* new_from_values(unsigned char qr, char* qname, unsigned short qtype, unsigned short qclass)
{
    struct DNS_PACKET *dnspacket = (struct DNS_PACKET*) malloc(sizeof(struct DNS_PACKET));

    struct DNS_HEADER *header = (struct DNS_HEADER*) malloc(sizeof(struct DNS_HEADER));
    struct QUESTION *question = (struct QUESTION*) malloc(sizeof(struct QUESTION));
    struct RES_RECORD *record = (struct RES_RECORD*) malloc(sizeof(struct RES_RECORD));

    dnspacket->header = header;
    dnspacket->question = question;
    dnspacket->record = record;

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
    dnspacket->question->qname = (char*) malloc(len_qname);
    memcpy(dnspacket->question->qname, qname, len_qname);

    question->qtype = qtype;
    question->qclass = qclass;

    dnspacket->record->name = (char*) malloc(sizeof(char)*2);
    dnspacket->record->rdata = (char*) malloc(sizeof(char)*2);

    record->rdata[0] = 0;
    record->rdata[1] = 2;
    record->name[0] = 0;
    record->name[1] = 2;


    return dnspacket;
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

int Binary_from_DNS(struct DNS_PACKET *dnspacket, char* resu){
    resu[0] = ((dnspacket->header->id) >> 8) & 0xFF;
    resu[1] = (dnspacket->header->id) & 0xFF;
    resu[2] = dnspacket->header->rd;
    resu[3] = dnspacket->header->tc;
    resu[4] = dnspacket->header->aa;
    resu[5] = dnspacket->header->qr;
    resu[6] = dnspacket->header->opcode;
    resu[7] = dnspacket->header->rcode;
    resu[8] = dnspacket->header->cd;
    resu[9] = dnspacket->header->ad;
    resu[10] = dnspacket->header->z;
    resu[11] = dnspacket->header->ra;
    resu[12] = ((dnspacket->header->q_count) >> 8) & 0xFF;
    resu[13] = (dnspacket->header->q_count) & 0xFF;
    resu[14] = ((dnspacket->header->ans_count) >> 8) & 0xFF;
    resu[15] = (dnspacket->header->ans_count) & 0xFF;
    resu[16] = ((dnspacket->header->auth_count) >> 8) & 0xFF;
    resu[17] = (dnspacket->header->auth_count) & 0xFF;
    resu[18] = ((dnspacket->header->add_count) >> 8) & 0xFF;
    resu[19] = (dnspacket->header->add_count) & 0xFF;
    //end header
    resu[20] = ((dnspacket->question->qtype) >> 8) & 0xFF;
    resu[21] = (dnspacket->question->qtype) & 0xFF;
    resu[22] = ((dnspacket->question->qclass) >> 8) & 0xFF;
    resu[23] = (dnspacket->question->qclass) & 0xFF;
    //end constant fields of question
    resu[24] = ((dnspacket->record->resource->type) >> 8) & 0xFF;
    resu[25] = (dnspacket->record->resource->type) & 0xFF;
    resu[26] = ((dnspacket->record->resource->rclass) >> 8) & 0xFF;
    resu[27] = (dnspacket->record->resource->rclass) & 0xFF;

    resu[28] = ((dnspacket->record->resource->ttl) >> 24) & 0xFF;
    resu[29] = ((dnspacket->record->resource->ttl) >> 16) & 0xFF;
    resu[30] = ((dnspacket->record->resource->ttl) >> 8) & 0xFF;
    resu[31] = (dnspacket->record->resource->ttl) & 0xFF;

    resu[32] = ((dnspacket->record->resource->data_len) >> 8) & 0xFF;
    resu[33] = (dnspacket->record->resource->data_len) & 0xFF;
    //end constant fields of record resource

    //Here we finish the attibutes of constant length. 
    int indice;
    char* pointer = resu;
    pointer = pointer + 34;
    int len_qname = ((unsigned char) dnspacket->question->qname[0])*256 + (unsigned char) dnspacket->question->qname[1];
    memcpy(pointer, dnspacket->question->qname, len_qname);
    //printf("%d\n", len_qname);
    pointer = pointer + len_qname;
    indice = 34 + len_qname;

    int len_rdata = ((unsigned char) dnspacket->record->rdata[0])*256 + (unsigned char) dnspacket->record->rdata[1];
    memcpy(pointer, dnspacket->record->rdata, len_rdata);
    pointer = pointer + len_rdata;
    indice = indice + len_rdata;
    
    int len_name = ((unsigned char) dnspacket->record->name[0])*256 + (unsigned char) dnspacket->record->name[1];
    memcpy(pointer, dnspacket->record->name, len_name);
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
 * dnspacket & dnspacket->header & dnspacket->question & dnspacket->record & dnspacket->record->resource
 */
struct DNS_PACKET* DNS_from_Binary(char* resu) // FALSE!
{
    struct DNS_PACKET *dnspacket = (struct DNS_PACKET*) malloc(sizeof(struct DNS_PACKET));
    
    dnspacket->header = (struct DNS_HEADER*) malloc(sizeof(struct DNS_HEADER));
    struct DNS_HEADER *header = dnspacket->header;
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

    dnspacket->question = (struct QUESTION*) malloc(sizeof(struct QUESTION));
    struct QUESTION *question = dnspacket->question;
    
    question->qtype = 256*resu[20]+resu[21];
    question->qclass = 256*resu[22]+resu[23];

    dnspacket->record = (struct RES_RECORD*) malloc(sizeof(struct RES_RECORD));
    struct RES_RECORD *record = dnspacket->record;
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
    dnspacket->question = question;
    dnspacket->record = record;

    return dnspacket;
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