#pragma once

#ifndef DNS_PACKET_H
#define DNS_PACKET_H


// 96 bits = 12 bytes in total
typedef struct HEADER
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
} HEADER;
 

typedef struct QUESTION
{
    /* qname
     * a sequence of labels: length (1 byte) followed by name
     * length must be 63 or less (first 2 bits are 0)
     * */
    unsigned char* qname;      // (at most 255 bytes)
    unsigned short qtype;      // (16 bits)
    unsigned short qclass;     // (16 bits)
} QUESTION;


typedef struct RR
{
    unsigned char  *name;      // (16 bits) (here 0 or c0 0c)
    unsigned short type;       // (16 bits)
    unsigned short rclass;     // (16 bits)
    unsigned long  ttl;        // (32 bits) (here 0)
    unsigned short rdlength;   // (16 bits)
    unsigned char  *rdata;     // (rdlength bytes)
} RR;


typedef struct DNS_PACKET
{
    HEADER         header;
    QUESTION       *question;
    RR             *answer;
    RR             *authority;
    RR             *additional;
} DNS_PACKET;


void print(DNS_PACKET packet);

void print(unsigned char *bytes);

/* Perform a DNS query by sending a packet combining msg and hostname */
//void DNS_Query(int, void*, char*, int, char*, char*, int);

//void get_dns_servers(); //Get the DNS servers from /etc/resolv.conf file on Linux

#endif