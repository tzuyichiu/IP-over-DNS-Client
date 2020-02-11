# IP-over-DNS tunneling (Client part)

## Overview

**IP-over-DNS tunneling** (or more common name **DNS tunneling**) is a method 
that allows the bypassing of usual network protection by wrapping up typical 
requests and responses (e.g. HTTP requests) into a standard DNS format, which 
tends to be less checked. An example of its advantages: if someone wants to 
connect to a charged Wi-Fi hotspot which seems not to be so secured, since DNS 
requests are less checked, these data would not be blocked. 

Generally speaking, this project consists of 2 parts: client and server. On the 
one hand, the client is the one that wants to connect to Internet so it 
includes a program that wraps up the requests into DNS format and unwraps DNS 
responses. On the other hand, the server is the one having access to Internet 
and serves as an intermediary that unwraps DNS requests and sends them to the 
real server that the client wants to communicate with, vice-versa for the 
responses.

One important step to have total control on data traffic is to create a virtual 
interface called **tap** on the local machine and modify the routing table to 
make sure that all traffic passes by this interface. The program *DNS_Client* 
reads data on tap and wraps them into DNS format. A stucture named *DNS_Packet* 
contains all attributes that correspond to the standard protocol, whose values 
will be assigned according to what is read on tap. Then we implemented in the 
file *DNS_Query.h* a function *DNS_to_Binary* which will transform DNS packets 
into byte arrays.


## Usage

In order to test and visualize this part of code:

- Install **openvpn** by typing for example: `sudo apt-get install openvpn`

- Launch: `sudo ./setup_tap.sh`

All traffic going to 8.8.8.8 will pass by the virtual interface **tap0**

- Compile the code by typing : `make`

- Launch: `./DNS_Client www.google.com 127.0.0.1`

The first argument www.google.com is meant to tell the DNS server who I want to 
communicate with; the second argument **127.0.0.1** should have been the IP 
address of the DNS server but here we are using the machine itself to do the 
test.

- Notice on the terminal some noise that is read on **tap0** (unknown reason) 
but if we try to "ping" 8.8.8.8 (in another terminal) we can see corresponding 
messages passing through: these are the data going to be wrapped into DNS and 
sent to the server.

- To kill **tap0**, launch: `sudo ./shut_tap.sh`


## Remarks

In fact, there is still some complication in this project that we didn't manage 
to resolve, especially the listen to the response. On the one hand, DNS uses 
UDP protocol that doesn't make "handshakes". As a result, the client has to 
continually send "empty" messages to ask the server whether there are responses 
for it as the server never informs the client spontaneously even if google, for 
example, already sent it back a response. On the other hand, the way that we 
transform the DNS packets into binary data doesn't follow exactly the standard 
DNS protocol (though really similar!), so a real DNS server would not 
understand. This could be easily fixed but since it is even more complicated to 
implement the server part, we decided to end up the project in a rather 
simplified way, as the communication client/server and the encoding/decoding 
process were accomplished successfully.