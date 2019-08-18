#ifndef DNS_UNSPLIT_H
#define DNS_UNSPLIT_H

int DNS_Unsplit(char*, char*,int);
void ReadName(char* buffer, int domainstart); //This will convert 3www6google3com to www.google.com

#endif