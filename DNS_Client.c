/*
 * Create 2 threads
 * 1. Sending thread: listen from tap0, transform the msg into a DNS request and send it to the DNS server
 * 2. Receiving thread: perform an DNS request permanently in order to get the answers from the DNS server
 * */

#include <stdio.h>  		//printf
#include <string.h> 		//strlen
#include <stdlib.h> 		//malloc
#include <sys/socket.h>
#include <arpa/inet.h> 		//inet_addr, inet_ntoa, ntohs etc
#include <netinet/in.h>
#include <unistd.h> 		//getpid
#include <pthread.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "DNS_Client.h"
#include "DNS_Query.h"
#include "DNS_Listen.h"
#include "ourStructs.h"

pthread_mutex_t sendmutex;
pthread_mutex_t receivemutex;

int nThread = 0;

int main(int argc, char *argv[])
{
	if (argc != 3) 
	{
		printf("Client must have exactly 2 parameters as input: Hostname and DNS server's IP.\n");
		return (EXIT_FAILURE);
	}

	char *host 			= argv[1];
	char *ip_dns_server = argv[2];
	int  tap_fd;
  	char *interface = "tap0";

  	// initialize tun/tap interface
  	if ((tap_fd = tun_alloc(interface, IFF_TAP)) < 0) 
  	{
    	printf("Error connecting to interface %s.\n", interface);
    	return (EXIT_FAILURE);
  	}

	printf("Successfully connected to interface %s.\n", interface);

	
	//create a socket (to communicate with DNS server)
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0); //IPv4 (AF_INET6 if IPv6)
	
	if (sockfd < 0) 
	{
		printf("Error creating socket.\n");
		return (EXIT_FAILURE);
	}
	printf("Socket created.\n\n");


	//arguments of functions "sending" & "receiving"
	struct thread_args args_value;

	args_value.tapfd  	   	 = tap_fd;
	args_value.sockfd 	   	 = sockfd;
	args_value.ip_dns_server = ip_dns_server;
	args_value.host 		 = host;

	struct thread_args *args = NULL;
	args = &args_value;


	//create threads in order to send messages while receiving data
	pthread_t sending_thread;
	pthread_t receiving_thread;
	
	if (pthread_mutex_init(&sendmutex, NULL) != 0)
    {
        printf("\n Mutex init failed.\n");
        return (EXIT_FAILURE);
    }

    if (pthread_mutex_init(&receivemutex, NULL) != 0)
    {
        printf("\n Mutex init failed\n");
        return (EXIT_FAILURE);
    }   
	
	if (pthread_create(&sending_thread, NULL, &sending, (void*) args)) 
	{
		fprintf(stderr, "Error creating sending thread.\n");
		return (EXIT_FAILURE);
	}
	
	if (pthread_create(&receiving_thread, NULL, &receiving, (void*) args)) 
	{
		fprintf(stderr, "Error creating receiving thread.\n");
		return (EXIT_FAILURE);
	}
	
	if (pthread_join(sending_thread, NULL)) 
	{
		fprintf(stderr, "Error joining sending thread.\n");
		return (EXIT_FAILURE);
	}
	
	if (pthread_join(receiving_thread, NULL)) 
	{
		fprintf(stderr, "Error joining receiving thread.\n");
		return (EXIT_FAILURE);
	}
	pthread_exit(NULL);
	
	//close socket
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

/* sending thread */

void *sending(void *args_void)
{
	pthread_mutex_lock(&sendmutex);
	nThread = 0;
	struct thread_args *args = (struct thread_args*) args_void;
	
	int   tap_fd        = args->tapfd;
	int   sockfd        = args->sockfd;
	char* ip_dns_server = args->ip_dns_server;
	char* host          = args->host;
	
	int ret;
    fd_set rd_set;
    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set);
    uint16_t nread, nwrite, plength;

	/* listen from tap0 */
	while (1)
	{
		nThread++;
		printf("%dth SENDING THREAD STARTED: LISTENING FROM tap0...\n\n", nThread);
		unsigned char msg[MAX_SZ];
		memset(msg, 0, MAX_SZ);
      	nread = cread(tap_fd, msg, MAX_SZ);
  	
  		// print msg
	    printf("Msg to encode:\n");
	    for (int i=0; i<nread; i++){
	        printf("%d ", msg[i]);
	    }
	    printf(" (%d bytes)\n", nread);

  		void* sockfd_void = NULL;
		sockfd_void = &sockfd;
		/* transform the msg into a DNS request and send it to the DNS server */
		DNS_Query(1, sockfd_void, msg, nread, host, ip_dns_server, T_CNAME);
		sleep(3);
    }
	
	pthread_mutex_unlock(&sendmutex);
}

/* receiving thread which asks if the DNS server has a packet to send back */

void *receiving(void *args_void)
{
	pthread_mutex_lock(&receivemutex);

	struct thread_args *args = (struct thread_args*) args_void;
	
	int   tapfd         = args->tapfd;
	int   sockfd        = args->sockfd;
	char* ip_dns_server = args->ip_dns_server;
	char* host          = args->host;

	void* sockfd_void = &sockfd;

	while (1)
	{
		printf("\nRECEIVING THREAD STARTED...\n\n");

		// see DNS_Query.c 
		DNS_Query(0, sockfd_void, ".", 0, host, ip_dns_server, T_TXT);
	
		// see DNS_Listen.c 
		unsigned char *received = (unsigned char*) Listen(sockfd_void, ip_dns_server);
		int len_qname = received[0]*256 + received[1];
		int indice_hostname = received[2]*256 + received[3];
		
		unsigned char *pointer = received + 5;
		pointer[indice_hostname - 5] = '\0';
		printf("Message decoded:\n\n");
    	for (int i = 0; i < indice_hostname - 5; i++)
        	printf("%d ", pointer[i]);
    
    	printf("\n");
		int nwrite = cwrite(tapfd, pointer, indice_hostname - 5);
		if (nwrite > 0){
			printf("\nDATA WRITTEN INTO TAPFD!\n\n\n");
		}
		printf("\n\n");
		free(received);

		sleep(3);
	}

	pthread_mutex_unlock(&receivemutex);
}

/* The following code was copied from:
 * http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/Firewall_VPN/files/simpletun.c
 */

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
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

	strcpy(dev, ifr.ifr_name);
	return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if ((nread = read(fd, buf, n)) < 0)
  {
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n)
{  
  int nwrite = 0;

  if ((nwrite=write(fd, buf, n)) < 0)
  {
    perror("Writing data");
    return 0;
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n (int fd, char *buf, int n)
{
	int nread, left = n;
	while (left > 0)
	{
		if ((nread = cread(fd, buf, left)) == 0)
			return 0;
	
		else 
		{
			left -= nread;
			buf += nread;
		}
	}
	return n;  
}