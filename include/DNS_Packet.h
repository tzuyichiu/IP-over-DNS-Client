#pragma once

#ifndef DNS_PACKET_H
#define DNS_PACKET_H


struct DNS_PACKET
{
    struct HEADER   *header;
    struct QUESTION *question;
    struct ANSWER   *answer;
};


// 96 bits = 12 bytes in total
struct HEADER
{
    unsigned short id;         // identification number (16 bits)

    unsigned char  qr     :1;  // query/response flag   (1 bit)
    unsigned char  opcode :4;  // purpose of message    (4 bits)
    unsigned char  aa     :1;  // authoritive answer    (1 bit)
    unsigned char  tc     :1;  // truncated message     (1 bit)
    unsigned char  rd     :1;  // recursion desired     (1 bit)
    
    unsigned char  ra     :1;  // recursion available   (1 bit)
    unsigned char  z      :3;  // its z reserved        (3 bits)
    unsigned char  rcode  :4;  // response code         (4 bits)
    
    unsigned short qdcount;    // nb question entries   (16 bits) (here 1)
    unsigned short ancount;    // nb answer entries     (16 bits) (here 0 or 1)
    unsigned short nscount;    // nb of authorities     (16 bits) (here 0)
    unsigned short arcount;    // nb of resources       (16 bits) (here 0)
};
 

struct QUESTION
{
    /* qname
     * a sequence of labels: length (1 byte) followed by name
     * length must be 63 or less (first 2 bits are 0)
     * */
    unsigned char* qname;      // (at most 255 bytes)
    unsigned short qtype;      // (16 bits)
    unsigned short qclass;     // (16 bits)
};


struct ANSWER
{
    unsigned char  *name;      // (16 bits) (here 0 or c0 0c)
    unsigned short type;       // (16 bits)
    unsigned short rclass;     // (16 bits)
    unsigned long  ttl;        // (32 bits) (here 0)
    unsigned short rdlength;   // (16 bits)
    unsigned char  *rdata;     // (rdlength bytes)
};


void print(DNS_PACKET packet);

/* Perform a DNS query by sending a packet combining msg and hostname */
void DNS_Query(int, void*, char*, int, char*, char*, int);

//void get_dns_servers(); //Get the DNS servers from /etc/resolv.conf file on Linux

struct DNS_PACKET* new_from_values(unsigned char qr, char* qname, unsigned short qtype, unsigned short qclass);

struct RES_RECORD* new_from_hash(char* name, unsigned short type, unsigned short rclass, unsigned int ttl, char* data);

int Binary_from_DNS(struct DNS_PACKET*, char*);

struct DNS_PACKET* DNS_from_Binary(char* resu);

unsigned char* substring(char* str,int start, int length);

#endif