#pragma once

/*
 * Modified from :
 * https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
 * which orginally performs a DNS Query from input hostname
 * 
 * Author : Silver Moon (m00n.silv3r@gmail.com)
 * Dated : 29/4/2009
 * */

#ifndef DNS_QUERY_H
#define DNS_QUERY_H

/* Perform a DNS query by sending a packet combining msg and hostname */
void DNS_Query(int, void*, char*, int, char*, char*, int);

//void get_dns_servers(); //Get the DNS servers from /etc/resolv.conf file on Linux

struct DNS_PACKET* new_from_values(unsigned char qr, char* qname, unsigned short qtype, unsigned short qclass);

struct RES_RECORD* new_from_hash(char* name, unsigned short type, unsigned short rclass, unsigned int ttl, char* data);

int Binary_from_DNS(struct DNS_PACKET*, char*);

struct DNS_PACKET* DNS_from_Binary(char* resu);

unsigned char* substring(char* str,int start, int length);

#endif