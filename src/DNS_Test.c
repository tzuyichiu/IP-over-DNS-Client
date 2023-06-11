#include <stdio.h>  //printf
#include <stdlib.h> //malloc

#include "DNS_Packet.h"
#include "DNS_Encode.h"
#include "DNS_Constructor.h"

/*
 * DNS_test: to test the encoding of messages into DNS packets
 * Please change DNS_Client to DNS_test in `Makefile` to execute this file.
 */
int main(int argc, char *argv[])
{
  int counter = 0;
  int len_msg = 1024;
  unsigned char msg[len_msg];

  // hardcoded the message
  for (int i = 0; i < len_msg - 1; i++)
    msg[i] = 1;
  msg[len_msg - 1] = '\0';

  printf("Original = (1024 bytes)\n");

  print_bytes(msg, len_msg);

  int nb_packets = len_msg / 250 + 1;
  DNS_PACKET *dns_packets = calloc(nb_packets, sizeof(DNS_PACKET));

  for (int i = 0; i < nb_packets; i++)
  {
    dns_packets[i].header.id = counter++;
    dns_packets[i].question = malloc(sizeof(QUESTION*));
    dns_packets[i].question->qname = malloc(255);
  }

  msg_to_DNSs(dns_packets, nb_packets, msg, len_msg);

  printf("Encoded = (%d packets)\n", nb_packets);

  unsigned char *dns_packets_bytes[nb_packets];

  for (int i = 0; i < nb_packets; i++)
  {
    print_DNS(dns_packets[i]);
    dns_packets_bytes[i] = malloc(1024);
    int len_bytes = DNS_to_bytes(dns_packets_bytes[i], dns_packets[i]);
    print_bytes(dns_packets_bytes[i], len_bytes);
    free(dns_packets_bytes[i]);
  }

  for (int i = 0; i < nb_packets; i++)
  {
    free(dns_packets[i].question->qname);
    free(dns_packets[i].question);
  }
  free(dns_packets);
  return 0;
}