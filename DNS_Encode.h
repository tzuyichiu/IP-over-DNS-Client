#pragma once

#ifndef DNS_SPLIT_H
#define DNS_SPLIT_H

int DNS_Split(unsigned char*, unsigned char*, int length);
int ChangetoDnsNameFormat(unsigned char*, unsigned char*, int); //This will convert www.google.com to 3www6google3com

#endif