#pragma once

#ifndef DNS_FLAG_H
#define DNS_FLAG_H

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

#endif