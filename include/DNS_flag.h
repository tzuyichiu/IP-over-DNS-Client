#pragma once

#ifndef DNS_FLAG_H
#define DNS_FLAG_H

#define MAX_SZ                4096
#define DEBUG                 1

#define QR_QUERY              0
#define QR_RESPONSE           1

#define OPCODE_QUERY          0
#define OPCODE_IQUERY         1
#define OPCODE_STATUS         2

#define AA_QUERY_NAME         0
#define AA_ANSWER_NAME        1

#define TC_NOT_TRUNCATED      0
#define TC_TRUNCATED          1

#define RD_REC_UNDESIRED      0
#define RD_REC_DESIRED        1

#define RA_REC_UNAVAILABLE    0
#define RA_REC_AVAILABLE      1

#define RCODE_NO_ERROR        0
#define RCODE_FORMAT_ERROR    1
#define RCODE_SERVER_FAILURE  2
#define RCODE_NAME_ERROR      3
#define RCODE_NOT_IMPLEMENTED 4
#define RCODE_REFUSED         5

#define QTYPE_A               1
#define QTYPE_NS              2
#define QTYPE_MD              3
#define QTYPE_MF              4
#define QTYPE_CNAME           5
#define QTYPE_SOA             6
#define QTYPE_MB              7
#define QTYPE_MG              8
#define QTYPE_MR              9
#define QTYPE_NULLRR          10
#define QTYPE_WKS             11
#define QTYPE_PTR             12
#define QTYPE_HINFO           13
#define QTYPE_MINFO           14
#define QTYPE_MX              15
#define QTYPE_TXT             16
#define QTYPE_AXFR            252
#define QTYPE_MAILB           253
#define QTYPE_MAILA           254
#define QTYPE_ALL             255

#define CLASS_IN              1
#define CLASS_CS              2
#define CLASS_CH              3
#define CLASS_HS              4
#define CLASS_ALL             255

/*
struct QR_CONSTANTS
{
    unsigned char QUERY           :1; //0
    unsigned char RESPONSE        :1; //1 
};


struct OPCODE_CONSTANTS
{
    unsigned char QUERY           :4; //0
    unsigned char IQUERY          :4; //1
    unsigned char STATUS          :4; //2
};


struct AA_CONSTANTS
{
    unsigned char QUERY_NAME      :1; //0
    unsigned char ANSWER_NAME     :1; //1
};


struct TC_CONSTANTS
{
    unsigned char NOT_TRUNCATED   :1; //0
    unsigned char TRUNCATED       :1; //1
};


struct RD_CONSTANTS
{
    unsigned char REC_UNDESIRED   :1; //0
    unsigned char REC_DESIRED     :1; //1   
};


struct RA_CONSTANTS
{
    unsigned char REC_UNAVAILABLE :1; //0
    unsigned char REC_AVAILABLE   :1; //1
};


struct RCODE_CONSTANTS
{
    unsigned char NO_ERROR        :4; //0
    unsigned char FORMAT_ERROR    :4; //1
    unsigned char SERVER_FAILURE  :4; //2
    unsigned char NAME_ERROR      :4; //3
    unsigned char NOT_IMPLEMENTED :4; //4
    unsigned char REFUSED         :4; //5
};


struct QTYPE_CONSTANTS
{
    unsigned short A;                 //1
    unsigned short NS;                //2
    unsigned short MD;                //3
    unsigned short MF;                //4
    unsigned short CNAME;             //5
    unsigned short SOA;               //6
    unsigned short MB;                //7
    unsigned short MG;                //8
    unsigned short MR;                //9
    unsigned short NULLRR;            //10
    unsigned short WKS;               //11
    unsigned short PTR;               //12
    unsigned short HINFO;             //13
    unsigned short MINFO;             //14
    unsigned short MX;                //15
    unsigned short TXT;               //16
    unsigned short AXFR;              //252
    unsigned short MAILB;             //253
    unsigned short MAILA;             //254
    unsigned short ALL;               //255 
};


struct CLASS_CONSTANTS
{
    unsigned short IN;                //1
    unsigned short CS;                //2
    unsigned short CH;                //3
    unsigned short HS;                //4
    unsigned short ALL;               //255
};
*/
#endif