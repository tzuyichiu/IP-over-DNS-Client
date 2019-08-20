#include <stdio.h>  //printf
#include <string.h> //strlen
#include <stdlib.h> //malloc

#include "DNS_Encode.h"
#include "DNS_flag.h"


/*
 * Split the message into sections of 63 bits (because in QNAME each word between the dots only has 64 bits)
 * The first word can only have 62 bits ("d" in front and "." behind)
 * The others can have 63 ("." behind)
 * */

int DNS_Split(unsigned char* split, unsigned char* msg, int length)
{
	int comp_spl = 0;
	int comp_msg = 0;
	int size_pack = 58;

	printf("Msg split:\n");
	while (1)
	{
		for (int j=0; j<size_pack; j++)
		{
			if (comp_msg < length)
			{
				split[comp_spl] = msg[comp_msg];
				printf("%d ", msg[comp_msg]);
				comp_spl++;
				comp_msg++;
			}
			else {
				printf(" (%d bytes)\n", comp_spl);
				return comp_spl;
			}
		}
		if (comp_msg+1 < length)
		{
			split[comp_spl] = '.';
			printf(". ");
			comp_spl++;
		}
		else {
			printf(" (%d bytes)\n", comp_spl);
			return comp_spl;
		}
		size_pack = 63;
	}
}


/*
 * to_Qname_format
 *
 * if msg = "www.google.com"
 * then 3www6google3com0 will be stocked into qname
 * return 1+3+1+6+1+3+1=16 offset
 * */
int to_Qname_format(unsigned char* qname, unsigned char* msg, int len_msg) 
{   
    int run_qname = 0; 
    int run_label = 1;
    int run_msg = 0;

    qname[0] = 0;

    while (run_msg < len_msg)
    {
        if (msg[run_msg] != '.')
        {
        	qname[run_qname]++;
        	qname[run_qname+run_label] = msg[run_msg];
        	run_label++;
        }
        else
    	{
	        run_qname += run_label;
	        qname[run_qname] = 0;
	        run_label = 1;
        }
        run_msg++;
    }
    run_qname += run_label;
    qname[run_qname] = 0;
    return run_qname+1;
}


/*
 * from_Qname_format
 *
 * if msg = 3www6google3com0
 * then "www.google.com" will be stocked into qname
 * return 3+1+6+1+3=14 string length
 * */
int from_Qname_format(unsigned char* msg, unsigned char* qname, int len_qname) 
{   
	int run_msg = 0;
	int run_qname = 0;
	int run_label = 1;

	while (run_qname < len_qname)
	{
		while (run_label <= qname[run_qname])
		{
			msg[run_msg] = qname[run_qname+run_label];
			run_label++;
			run_msg++;
		}
		run_qname += run_label;
		
		if (run_qname != len_qname)
			msg[run_msg] = '.';
		run_label = 1;
		run_msg++;
	}
	return run_msg-1;
}


// testing purposes (comment include files)
int main(int argc, char* argv[])
{
    char msg[128];

	printf("Enter the msg to encode: ");
	fgets(msg, 128, stdin);

	// Remove trailing newline, if there is.
	if ((strlen(msg) > 0) && (msg[strlen(msg)-1] == '\n'))
		msg[strlen(msg)-1] = '\0';
	
	char *dns = malloc(128);
	printf("Original = (%zu bytes) %s\n", strlen(msg), msg);
	
	int offset = to_Qname_format(dns, msg, strlen(msg)); 
	printf("Encoded = (%d bytes) ", offset);
	
	for (int i=0; i<offset; i++)
	{
		if (dns[i] >= 32 && dns[i] <= 126)
			printf("%c", dns[i]);
		else
			printf("%d", dns[i]);
	}
	printf("\n");
	
	int msg_len = from_Qname_format(msg, dns, offset-1);
	free(dns);

	printf("Decoded = (%d bytes) %.*s\n", msg_len, msg_len, msg);
	return 0;
}