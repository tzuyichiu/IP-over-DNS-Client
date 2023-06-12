#pragma once

#ifndef ENCODER_H
#define ENCODER_H

/*
 * msg_to_qname
 *
 * Split the message into labels of 63 bytes following its length taking 1 byte.
 * */
int msg_to_qname(unsigned char *qname, unsigned char *msg, unsigned char *end);

/*
 * qname_to_msg
 *
 * if qname = 3www6google3com0,
 * then "wwwgooglecom" will be stocked into bytes.
 * @return 3+6+3=12 string length
 * */
int qname_to_msg(unsigned char *msg, unsigned char *qname);

/*
 * msg_to_DNSs
 *
 * Construct a sequence of DNS requesting packets from the received msg by
 * transforming them into qnames, then stock then corresponding DNS requests
 * into dns_packets.
 * */
void msg_to_DNSs(DNS_PACKET **dns_packets, int nb_packets, unsigned char *msg, int len_msg);

/*
 * DNS_to_bytes
 *
 * transform the DNS_PACKET into a bytes array.
 * @return: the length of the bytes array.
 * */
int DNS_to_bytes(unsigned char *bytes, DNS_PACKET *dns_packet);

/*
 * bytes_to_DNS
 *
 * transform the bytes array of length len_bytes into a DNS packet.
 * @return: the length of bytes read.
 * */
int bytes_to_DNS(DNS_PACKET *dns_packet, unsigned char *bytes);

#endif