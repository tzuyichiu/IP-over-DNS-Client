#include <stdio.h>  // printf
#include <stdlib.h> // malloc

#include "packet.h"
#include "encoder.h"
#include "flag.h"

/*
 * test: to test the encoding of messages into DNS packets
 * Please change DNS_Client to DNS_test in `Makefile` to execute this file.
 */
int main(int argc, char *argv[])
{
  int counter = 0;
  int nread = 512;
  unsigned char msg[nread];

  // hardcoded the message
  for (int i = 0; i < nread - 1; i++)
    msg[i] = 1 + i % 255;
  msg[nread - 1] = '\0';

  printf("Original = (%d bytes)\n", nread);

  print_bytes(msg, nread);

  int nb_packets = nread / INFO_PER_QNAME + (nread % INFO_PER_QNAME ? 1 : 0);
  DNS_PACKET **dns_packets = calloc(nb_packets, sizeof(DNS_PACKET*));

  for (int i = 0; i < nb_packets; i++)
  {
    dns_packets[i] = malloc(sizeof(DNS_PACKET));
    dns_packets[i]->header.id = counter++;
    dns_packets[i]->question = malloc(sizeof(QUESTION*));
    dns_packets[i]->question->qname = calloc(QNAME_MAX_SZ, 1);
  }

  msg_to_DNSs(dns_packets, nb_packets, msg, nread);

  printf("\nEncoded = (%d packets)\n", nb_packets);

  unsigned char *dns_packets_bytes[nb_packets];

  for (int i = 0; i < nb_packets; i++)
  {
    print_DNS(dns_packets[i]);
    dns_packets_bytes[i] = malloc(UDP_MAX_SZ);
    int len_bytes = DNS_to_bytes(dns_packets_bytes[i], dns_packets[i]);
    print_bytes(dns_packets_bytes[i], len_bytes);
    free(dns_packets_bytes[i]);
  }

  for (int i = 0; i < nb_packets; i++)
  {
    free(dns_packets[i]->question->qname);
    free(dns_packets[i]->question);
    free(dns_packets[i]);
  }
  free(dns_packets);
  return 0;
}