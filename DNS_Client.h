/*Create 2 threads
 *1. Sending thread: listen from tap0, transform the msg into an DNS request and send it to the DNS server
 *2. Receiving thread: perform an DNS request permanently in order to get the answers from the DNS server
 */

#ifndef DNS_CLIENT_H
#define DNS_CLIENT_H

struct sockfd_ipDNS_host {
	int tapfd;
	int sockfd;
	char *ip_dns_server;
	char *host;
};

void *sending(void *sih_void);
void *receiving(void *sih_void);
int tun_alloc(char *dev, int flags);
int cread(int fd, char *buf, int n);
int cwrite(int fd, char *buf, int n);
int read_n(int fd, char *buf, int n);

#endif