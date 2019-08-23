#pragma once

#ifndef DNS_ENCODE_H
#define DNS_ENCODE_H

/*
 * to_qname_format
 *
 * Split the message into labels of 63 bytes following its length taking 1 byte
 * Since the size limit of Qname is 255 bytes, so here we limit len_packet <= 250
 * */
int to_qname_format(unsigned char* qname, unsigned char* packet, int len_packet);



typedef struct {
    int nb_packets;
    int last_offset;
} info_qnames;


/*
 * bytes_to_qnames
 *
 * Split the message into a sequence of msg in qname format
 * [63 bytes*3 + 61 bytes (250 bytes)][63 bytes*3 + 61 bytes (250 bytes)][...]
 * -> [63(...)63(...)63(...)61(...)\0 (254+1 bytes)][63(...)63(...)63(...)61(...)\0 (254+1 bytes)][...]
 * @return info_qnames including the number of packets and the length of the last packet
 * */
info_qname bytes_to_qnames(unsigned char** qnames, unsigned char* msg, int len_msg)

/*
 * qname_to_bytes
 *
 * if qname = 3www6google3com0
 * then "wwwgooglecom" will be stocked into msg
 * @return 3+6+3=12 string length
 * */
int qname_to_bytes(unsigned char* msg, unsigned char* qname);

/*
 * DNS_to_bytes
 *
 * transform the DNS_PACKET into a bytes array
 * @return the length of the bytes array
 * */
int DNS_to_bytes(unsigned char* bytes, DNS_PACKET dns_packet);

/*
 * bytes_to_DNS
 *
 * transform the bytes array of length len_bytes into a DNS_PACKET and stock in dns_packet
 * */
void bytes_to_DNS(DNS_PACKET dns_packet, unsigned char* bytes, int len_bytes)


#endif