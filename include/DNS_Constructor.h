#pragma once

#ifndef DNS_CONSTRUCTOR_H
#define DNS_CONSTRUCTOR_H

/*
 * to_qname
 *
 * Split the message into labels of 63 bytes following its length taking 1 byte
 * Since the size limit of Qname is 255 bytes, here we limit len_packet <= 250
 * */
void to_qname(unsigned char *qname, unsigned char *packet, int len_packet);

/*
 * msg_to_qnames
 *
 * Split the message into a sequence in qname format
 *    [63 bytes*3 + 61 bytes (250 bytes)]
 *    [63 bytes*3 + 61 bytes (250 bytes)][...]
 * -> [63(...)63(...)63(...)61(...)\0 (250+1 bytes)]
 *    [63(...)63(...)63(...)61(...)\0 (250+1 bytes)][...]
 * */
void msg_to_qnames(unsigned char **qnames, unsigned char *msg, int len_msg);

/*
 * msg_to_DNSs
 *
 * Construct a sequence of DNS requesting packets from the received msg by
 * transforming them into qnames, then stock then corresponding DNS requests
 * into dns_packets
 * */
void msg_to_DNSs(DNS_PACKET *dns_packets, int nb_packets, unsigned char *msg, int len_msg);

#endif