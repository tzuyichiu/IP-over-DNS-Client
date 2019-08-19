#pragma once

/*
 * Modified from :
 * https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
 * which orginally performs a DNS Query from input hostname
 * 
 * Author : Silver Moon (m00n.silv3r@gmail.com)
 * Dated : 29/4/2009
 * */


#ifndef DNS_LISTEN_H
#define DNS_LISTEN_H

char* Listen(void* sockfd_void, char *ip_dns_server);

#endif