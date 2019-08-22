#pragma once

#ifndef DNS_ENCODE_H
#define DNS_ENCODE_H

/*
 * to_Qname_format
 *
 * Split the message into labels of 63 bytes following its length taking 1 byte
 * Since the size limit of Qname is 255 bytes, so here we limit len_packet <= 250
 * */
int to_Qname_format(unsigned char* qname, unsigned char* packet, int len_packet);



typedef struct {
    int nb_packets;
    int last_offset;
} info_qname;

/*
 * to_Qnames
 *
 * Split the message into a sequence of msg in qname format
 * [63 bytes*3 + 61 bytes (250 bytes)][63 bytes*3 + 61 bytes (250 bytes)][...]
 * -> [63(...)63(...)63(...)61(...)\0 (254+1 bytes)][63(...)63(...)63(...)61(...)\0 (254+1 bytes)][...]
 * */
info_qname to_Qnames(unsigned char** qnames, unsigned char* msg, int len_msg)

/*
 * from_Qname_format
 *
 * if qname = 3www6google3com0
 * then "wwwgooglecom" will be stocked into msg
 * return 3+6+3=12 string length
 * */
int from_Qname(unsigned char* msg, unsigned char* qname, int len_qname);

#endif