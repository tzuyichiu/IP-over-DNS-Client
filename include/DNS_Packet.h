#pragma once

#ifndef DNS_PACKET_H
#define DNS_PACKET_H


struct DNS_PACKET
{
    struct HEADER   *header;
    struct QUESTION *question;
    struct RR       *rr;
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
    
    unsigned short qdcount;    // nb question entries   (16 bits)
    unsigned short ancount;    // nb answer entries     (16 bits)
    unsigned short nscount;    // nb of authorities     (16 bits)
    unsigned short arcount;    // nb of resources       (16 bits)
};
 

struct QUESTION
{
    /* qname
     * a sequence of labels: length (1 byte) followed by name
     * length must be 63 or less (first 2 bits are 0)
     * */
    char* qname;
    unsigned short qtype;
    unsigned short qclass;
};


struct RES_RECORD
{
    unsigned char *name;
    unsigned short type;
    unsigned short rclass;
    unsigned int   ttl;
    unsigned short rdlength;
    unsigned char *rdata;
};

#endif