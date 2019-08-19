#include <stdio.h>  //printf
#include <string.h> //strlen
#include <stdlib.h> //malloc

#include "DNS_Encode.h"
#include "flag.h"

/**
 * Split the message into sections of 63 bits (because in QNAME each word between the dots only has 64 bits)
 * The first word can only have 62 bits ("d" in front and "." behind)
 * The others can have 63 ("." behind)
 */

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
The following is modified from :
https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
which orginally performs a DNS Query from input hostname

Author : Silver Moon (m00n.silv3r@gmail.com)
Dated : 29/4/2009
*/

/*
 * This will convert www.google.com to 3www6google3com 
 * */
int ChangetoDnsNameFormat(unsigned char* qname, unsigned char* msg, int len_msg) 
{
    int run_qname = 0, run_msg = 0;
    msg[len_msg] = '.';
    
    printf("DNS Format:\n");
    for(int i=0; i<len_msg+1; i++) 
    {
        if(msg[i]=='.')
        {
            qname[run_qname] = i-run_msg;
            printf("%d ", i-run_msg);
            run_qname += 1;
            
            for (int j=0; j<i-run_msg; j++) 
            {
                qname[run_qname] = msg[run_msg+j];
                printf("%d ", msg[run_msg+j]);
                run_qname++;
            }
            run_msg = i+1;
        }
    }
    qname[run_qname] = '\0';
    printf(" (%d bytes)\n", run_qname);
    return run_qname;
}

/*
int main(int argc, char* argv[])
{
    char msg[128];

	printf("Enter the msg to encode: ");
	fgets(msg, 128, stdin);

	// Remove trailing newline, if there is.
	if ((strlen(msg) > 0) && (msg[strlen(msg)-1] == '\n'))
	{msg[strlen(msg)-1] = '\0';}
	
	char *dns = malloc(128);
	printf("Original = '%s'\n", msg);
	ChangetoDnsNameFormat(dns, msg); 

	printf("Encoded = '%s'\n", dns);
	free(dns);
	return 0;
}
*/