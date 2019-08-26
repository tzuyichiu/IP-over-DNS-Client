#pragma once

#ifndef DNS_CONSTRUCTOR_H
#define DNS_CONSTRUCTOR_H

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
 * msg_to_qnames
 *
 * Split the message into a sequence of msg in qname format
 * [63 bytes*3 + 61 bytes (250 bytes)][63 bytes*3 + 61 bytes (250 bytes)][...]
 * -> [63(...)63(...)63(...)61(...)\0 (254+1 bytes)][63(...)63(...)63(...)61(...)\0 (254+1 bytes)][...]
 * @return info_qnames including the number of packets and the length of the last packet
 * */
info_qnames msg_to_qnames(unsigned char** qnames, unsigned char* msg, int len_msg);


/*
 * msg_to_DNSs
 * 
 * Construct a sequence of DNS packets by transforming msg (byte arrays) into qname format 
 * and each generated qname will correspond to a DNS packet 
 * @return the number of DNS packets constructed
 * */

int msg_to_DNSs(DNS_Packet* DNSs, unsigned char* msg, int len_msg);


#endif