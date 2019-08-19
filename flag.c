#include "flag.h"

const int MAX_SZ = 32768;

// DNS response part
const int T_A     = 1;  // Ipv4 address
const int T_NS    = 2;  // nameserver
const int T_CNAME = 5;  // canonical name
const int T_SOA   = 6;  // start of authority zone
const int T_PTR   = 12; // domain name pointer
const int T_MX    = 15; // mail server
const int T_TXT   = 16;