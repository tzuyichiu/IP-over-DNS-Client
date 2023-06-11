/*
 * Listen from tap0, transform the msg into a DNS request &
 * send it to the DNS server
 * */

#include <stdio.h> //printf
#include <string.h>
#include <stdlib.h> //malloc
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr, inet_ntoa, ntohs etc
#include <netinet/in.h>
#include <unistd.h> //getpid
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "DNS_Client.h"
#include "DNS_Packet.h"
#include "DNS_flag.h"
#include "DNS_Encode.h"
#include "DNS_Constructor.h"

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("Usage: DNS_Client hostname ip_dns_server.\n");
		return (EXIT_FAILURE);
	}

	char *host = argv[1];
	char *ip_dns_server = argv[2];
	int tap_fd;
	char *interface = "tap0";

	// initialize tun/tap interface
	if ((tap_fd = tun_alloc(interface, IFF_TAP)) < 0)
	{
		printf("Error connecting to interface %s.\n", interface);
		return (EXIT_FAILURE);
	}

	if (DEBUG)
		printf("Successfully connected to interface %s.\n", interface);

	// create a socket (to communicate with DNS server)
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0); // IPv4 (AF_INET6 if IPv6)

	if (sockfd < 0)
	{
		printf("Error creating socket.\n");
		return (EXIT_FAILURE);
	}

	if (DEBUG)
		printf("Socket created.\n\n");

	send_DNS(tap_fd, sockfd, ip_dns_server, host);

	// close socket
	if (close(sockfd) == 0)
	{
		printf("Socket closed.\n");
		return (EXIT_SUCCESS);
	}
	else
	{
		printf("Error closing socket.\n");
		return (EXIT_FAILURE);
	}
}

void send_DNS(int tap_fd, int sockfd, char *ip_dns_server, char *host)
{
	fd_set rd_set;
	FD_ZERO(&rd_set);
	FD_SET(tap_fd, &rd_set);
	uint16_t nread, nwrite, plength;

	unsigned char msg[MAX_SZ];
	unsigned char bytes[MAX_SZ];	
	int counter = 0;

	/* listen from tap0 */
	while (1)
	{
		if (DEBUG)
			printf("LISTENING FROM tap0...\n");

		memset(msg, 0, MAX_SZ);
		memset(bytes, 0, MAX_SZ);
		nread = cread(tap_fd, msg, MAX_SZ);

		if (DEBUG)
		{
			printf("Msg to encode:\n");
			for (int i = 0; i < nread; i++)
				printf("%02x ", msg[i]);
			printf(" (%d bytes)\n", nread);
		}

		// bind socket
		void *sockfd_void = &sockfd;
		struct sockaddr_in to_IPv4;
		memset(&to_IPv4.sin_zero, 0, sizeof(to_IPv4.sin_zero));
		to_IPv4.sin_family = AF_INET;
		to_IPv4.sin_port = htons(53);
		struct in_addr address;

		if (!inet_pton(AF_INET, ip_dns_server, &address))
		{
			printf("Invalid server IP address.\n");
			break;
		}

		to_IPv4.sin_addr = address;
		const struct sockaddr *to = (struct sockaddr *)&to_IPv4;

		// dns packets
  	int nb_packets = nread / 250 + 1;
  	DNS_PACKET *dns_packets = calloc(nb_packets, sizeof(DNS_PACKET));

  	for (int i = 0; i < nb_packets; i++)
  	{
			dns_packets[i].header.id = (counter++) % 65536;
   		dns_packets[i].question = malloc(sizeof(QUESTION*));
    	dns_packets[i].question->qname = malloc(255);
  	}

  	msg_to_DNSs(dns_packets, nb_packets, msg, nread);

		if (DEBUG)
			printf("Encoded = (%d packets)\n", nb_packets);

  	unsigned char *dns_packets_bytes[nb_packets];

		for (int i = 0; i < nb_packets; i++)
		{
			if (DEBUG)
				print_DNS(dns_packets[i]);
			dns_packets_bytes[i] = malloc(1024);
			int nb_bytes = DNS_to_bytes(dns_packets_bytes[i], dns_packets[i]);
			int nb_bytes_sent = sendto(sockfd, bytes, nb_bytes, 0, to, sizeof(*to));
			if (DEBUG)
				print_bytes(dns_packets_bytes[i], nb_bytes);
			free(dns_packets_bytes[i]);
		}

		for (int i = 0; i < nb_packets; i++)
		{
			free(dns_packets[i].question->qname);
			free(dns_packets[i].question);
		}
		free(dns_packets);
	}
}

/* The following code was copied from:
 * http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/Firewall_VPN/files/simpletun.c
 */

/*
 * tun_alloc
 *      allocates or reconnects to a tun/tap device.
 * */
int tun_alloc(char *dev, int flags)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
	{
		perror("Opening /dev/net/tun");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
	{
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}
	return fd;
}

/*
 * cread
 *      read routine that checks for errors and exits if an error is returned
 * */
int cread(int fd, char *buf, int n)
{
	int nread;

	if ((nread = read(fd, buf, n)) < 0)
	{
		perror("Reading data");
		exit(EXIT_FAILURE);
	}
	return nread;
}