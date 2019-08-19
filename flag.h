#pragma once

#ifndef OUR_STRUCTS_H
#define OUR_STRUCTS_H

const int MAX_SZ;

// DNS response part
const int T_A;
const int T_NS;
const int T_CNAME;
const int T_SOA;
const int T_PTR;
const int T_MX;
const int T_TXT;


struct thread_args 
{
	int  tapfd;
	int  sockfd;
	char *ip_dns_server;
	char *host;
};


struct DNS_PACKET
{
    struct DNS_HEADER *header;
    struct QUESTION   *question;
    struct RES_RECORD *record;
};


struct DNS_HEADER
{
    unsigned short id;         // identification number

    unsigned char  rd     :1;  // recursion desired
    unsigned char  tc     :1;  // truncated message
    unsigned char  aa     :1;  // authoritive answer
    unsigned char  qr     :1;  // query/response flag
    unsigned char  opcode :4;  // purpose of message

    unsigned char  rcode  :4;  // response code
    unsigned char  cd     :1;  // checking disabled
    unsigned char  ad     :1;  // authenticated data
    unsigned char  z      :1;  // its z! reserved
    unsigned char  ra     :1;  // recursion available
 
    unsigned short q_count;    // number of question entries
    unsigned short ans_count;  // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count;  // number of resource entries
};
 
// Constant sized fields of query structure
struct QUESTION
{
    /* qname
     * 1st and 2nd byte correspond to the qname's length
     * 3rd and 4th correspond to the hostname's indice in qname
     * */
    char* qname;
    unsigned short qtype;
    unsigned short qclass;
};
 
// constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short rclass;
    unsigned int   ttl;
    unsigned short data_len;
};

#pragma pack(pop)
// pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

#endif