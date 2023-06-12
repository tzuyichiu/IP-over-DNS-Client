/*
 * Modified from :
 * https://gist.github.com/fffaraz/9d9170b57791c28ccda9QNAME_MAX_SZb48315168
 * which orginally performs a DNS Query from input hostname
 *
 * Author : Silver Moon (m00n.silv3r@gmail.com)
 * Dated : 29/4/2009
 * */

#include <stdio.h>      // printf
#include <string.h>     // strlen
#include <stdlib.h>     // malloc
#include <sys/socket.h> // sockets
#include <arpa/inet.h>  // inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>

#include "packet.h"
#include "encoder.h"
#include "flag.h"

void print_DNS(DNS_PACKET *dns_packet)
{
  HEADER header = dns_packet->header;
  printf("\n***************\n");
  printf("*  DNS Start  *\n");
  printf("***************\n");
  printf("\n** Header **\n");
  printf("header.id:                  %02x %02x\n",
         (header.id >> 8) & 0xFF, header.id & 0xFF);
  printf("header.qr:                  %02x\n", header.qr & 0xFF);
  printf("header.opcode:              %02x\n", header.opcode & 0xFF);
  printf("header.aa:                  %02x\n", header.aa & 0xFF);
  printf("header.tc:                  %02x\n", header.tc & 0xFF);
  printf("header.rd:                  %02x\n", header.rd & 0xFF);
  printf("header.ra:                  %02x\n", header.ra & 0xFF);
  printf("header.z:                   %02x\n", header.z & 0xFF);
  printf("header.rcode:               %02x\n", header.rcode & 0xFF);
  printf("header.qdcount:             %02x %02x\n",
         (header.qdcount >> 8) & 0xFF, header.qdcount & 0xFF);
  printf("header.ancount:             %02x %02x\n",
         (header.ancount >> 8) & 0xFF, header.ancount & 0xFF);
  printf("header.nscount:             %02x %02x\n",
         (header.nscount >> 8) & 0xFF, header.nscount & 0xFF);
  printf("header.arcount:             %02x %02x\n",
         (header.arcount >> 8) & 0xFF, header.arcount & 0xFF);

  QUESTION question;
  for (int i = 0; i < header.qdcount; i++)
  {
    question = dns_packet->question[i];
    printf("\n** Question %d **\n", i);
    printf("question.qname:             ");
    for (int j = 0; j < QNAME_MAX_SZ; j++)
      printf("%02x ", question.qname[j]);
    printf("\n");
    printf("question.qtype:             %02x\n", question.qtype && 0xFF);
    printf("question.qclass:            %02x\n", question.qclass && 0xFF);
  }

  RR answer;
  for (int i = 0; i < header.ancount; i++)
  {
    answer = dns_packet->answer[i];
    printf("\n** Answer %d **\n", i);
    printf("answer.name:                ");
    for (int j = 0; j < QNAME_MAX_SZ; j++)
      printf("%02x ", dns_packet->answer->name[j]);
    printf("\n");

    printf("answer.type:                %02x\n", answer.type & 0xFF);
    printf("answer.rclass:              %02x\n", answer.rclass & 0xFF);
    printf("answer.ttl:                 %02lu\n", answer.ttl & 0xFF);
    printf("answer.rdlength:            %02x\n", answer.rdlength & 0xFF);

    printf("answer->rdata:              ");
    for (int j = 0; j < answer.rdata[0]; j++)
      printf("%02x ", answer.rdata[j]);
    printf("\n");
  }

  RR authority;
  for (int i = 0; i < header.nscount; i++)
  {
    printf("\n** Authority %d **\n", i);
    printf("authority.name:       ");
    for (int j = 0; j < QNAME_MAX_SZ; j++)
      printf("%d ", authority.name[j]);
    printf("\n");

    printf("authority.type:             %02x\n", authority.type & 0xFF);
    printf("authority.rclass:           %02x\n", authority.rclass & 0xFF);
    printf("authority.ttl:              %02lu\n", authority.ttl & 0xFF);
    printf("authority.rdlength:         %02x\n", authority.rdlength & 0xFF);

    printf("authority.rdata:            ");
    for (int j = 0; j < authority.rdlength; j++)
      printf("%02x ", authority.rdata[j]);
    printf("\n");
  }

  RR additional;
  for (int i = 0; i < header.arcount; i++)
  {
    additional = dns_packet->additional[i];
    printf("additional.name:             ");
    for (int j = 0; j < QNAME_MAX_SZ; j++)
      printf("%02x ", dns_packet->additional->name[j]);
    printf("\n");

    printf("additional.type:            %02x\n", additional.type & 0xFF);
    printf("additional.rclass:          %02x\n", additional.rclass & 0xFF);
    printf("additional.ttl:             %02lu\n", additional.ttl & 0xFF);
    printf("additional.rdlength:        %02x\n", additional.rdlength & 0xFF);

    printf("additional->rdata:          ");
    for (int j = 0; j < additional.rdlength; j++)
      printf("%02x ", additional.rdata[j]);
    printf("\n");
  }
  printf("\n*************\n");
  printf("*  DNS End  *\n");
  printf("*************\n");
}

void print_bytes(unsigned char *bytes, int len_bytes)
{
  printf("\n");
  for (int i = 0; i < len_bytes; i++)
    printf("%02x ", bytes[i]);
  printf("(%d bytes)\n", len_bytes);
}

/*
 * Get the DNS servers from /etc/resolv.conf file on Linux

void get_dns_servers()
{
  FILE *fp;
  char line[200] , *p;
  if((fp = fopen("/etc/resolv.conf" , "r")) == NULL)
    printf("Failed opening /etc/resolv.conf file \n");

  while(fgets(line , 200 , fp))
  {
    if (line[0] == '#') continue;
    if (strncmp(line , "nameserver" , 10) == 0)
    {
      p = strtok(line , " ");
      p = strtok(NULL , " ");

      //p now is the dns ip :)
      //????
    }
  }

  strcpy(dns_servers[0] , "208.67.222.222");
  strcpy(dns_servers[1] , "208.67.220.220");
}
*/