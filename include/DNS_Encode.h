#pragma once

#ifndef DNS_ENCODE_H
#define DNS_ENCODE_H

/*
 * qname_to_bytes
 *
 * if qname = 3www6google3com0
 * then "wwwgooglecom" will be stocked into msg
 * @return 3+6+3=12 string length
 * */
int qname_to_bytes(unsigned char *msg, unsigned char *qname);

/*
 * DNS_to_bytes
 *
 * transform the DNS_PACKET into a bytes array
 * @return the length of the bytes array
 * */
int DNS_to_bytes(unsigned char *bytes, DNS_PACKET dns_packet);

/*
 * bytes_to_DNS
 *
 * transform the bytes array of length len_bytes into a DNS_PACKET and stock in dns_packet
 * */
void bytes_to_DNS(DNS_PACKET dns_packet, unsigned char *bytes, int len_bytes)


#endif