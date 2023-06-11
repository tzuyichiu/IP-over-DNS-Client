#pragma once

/*
 * Create 2 threads
 * 1. Sending thread: listen from tap0, transform the msg into a DNS request and send it to the DNS server
 * 2. Receiving thread: perform an DNS request permanently in order to get the answers from the DNS server
 * */

#ifndef DNS_CLIENT_H
#define DNS_CLIENT_H

struct thread_args
{
	int tapfd;
	int sockfd;
	char *ip_dns_server;
	char *host;
};

void send_DNS(int tap_fd, int sockfd, char *ip_dns_server, char *host);
int tun_alloc(char *dev, int flags);
int cread(int fd, char *buf, int n);

#endif