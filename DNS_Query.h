//Change our message into a DNS Query

/*
Modified from :
https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
which orginally performs a DNS Query from input hostname

Author : Silver Moon (m00n.silv3r@gmail.com)
Dated : 29/4/2009
*/

#ifndef DNS_QUERY_H
#define DNS_QUERY_H

/* Perform a DNS query by sending a packet combining msg and hostname */
void DNS_Query(int, void*, char*, int, char*, char*, int);
//void get_dns_servers(); //Get the DNS servers from /etc/resolv.conf file on Linux

//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char qr :1; // query/response flag
    unsigned char opcode :4; // purpose of message

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
    // In qname:
    // 1st and 2nd byte correspond to the qname's length
    // 3rd and 4th correspond to the hostname's indice in qname
    char* qname;
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short rclass;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

//Structure of a Packet
struct DNS_PACKET
{
    struct DNS_HEADER *header;
    struct QUESTION *question;
    struct RES_RECORD *record;
};

struct DNS_PACKET* new_from_values(unsigned char qr,
                                   char* qname, 
                                   unsigned short qtype, 
                                   unsigned short qclass);

struct RES_RECORD* new_from_hash(char* name,
                                unsigned short type,
                                unsigned short rclass,
                                unsigned int ttl,
                                char* data);

int Binary_from_DNS(struct DNS_PACKET*, char*);

struct DNS_PACKET* DNS_from_Binary(char* resu);

unsigned char* substring(char* str,int start, int length);

#endif