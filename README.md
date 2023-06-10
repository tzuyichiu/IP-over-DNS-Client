# IP-over-DNS tunneling (Client part)

## Overview

IP-over-DNS tunneling, also known as DNS tunneling, is a method that 
circumvents typical network protections by encapsulating regular requests and 
responses (such as HTTP requests) into the standard DNS format, which is often 
subject to less scrutiny. 
One advantage of this approach is evident when attempting to connect to a 
charged Wi-Fi hotspot that may not have robust security measures in place. 
Since DNS requests undergo less inspection, the transmitted data is less likely 
to be blocked.

The project can be divided into two main components: the client and the server. 
The client is responsible for establishing the Internet connection and includes 
a program that converts requests into the DNS format and decodes DNS responses. 
On the other hand, the server acts as an intermediary, receiving the DNS 
requests, unpacking them, and forwarding them to the actual server that the 
client wishes to communicate with. The process is reversed for the responses.

A crucial step in gaining full control over the data traffic is the creation of 
a virtual interface called "tap" on the local machine. 
Additionally, the routing table is modified to ensure that all traffic is 
routed through this interface. The `DNS_Client` program reads data from the tap 
interface and encapsulates it into the DNS format. 
The `DNS_Packet` structure encompasses all the attributes corresponding to 
the standard protocol, and their values are assigned based on the information 
retrieved from the tap interface. Finally, we implemented the `DNS_to_Binary`
function in the `DNS_Query.h` file, which converts DNS packets into byte arrays.

## Usage

To test and visualize this portion of the code, please follow the steps below:
1. Install **openvpn** by running the following command, for example: 
```sh
$ sudo apt-get install openvpn
```

2. Launch the setup script by executing: 
```sh
$ sudo ./setup_tap.sh
```
This will ensure that all traffic directed towards `8.8.8.8` will pass through 
the virtual interface `tap0`.

3. Compile the code by entering:
```sh
$ make
```

4. Launch the DNS client by running: 
```sh
$ ./DNS_Client www.google.com 127.0.0.1
```
The first argument, `www.google.com`, specifies the target server for 
communication. 
The second argument, `127.0.0.1`, would typically be the IP address of the DNS 
server. 
However, in this test, we are using the local machine itself.

5. Take note of any noise displayed on the terminal, which is read from `tap0` 
for an unknown reason. 
However, if you attempt to **ping** 8.8.8.8 in another terminal, you will observe 
corresponding messages passing through. 
These are the data that will be wrapped into DNS format and sent to the server.

6. To terminate the `tap0` interface, execute: 
```sh
$ sudo ./shut_tap.sh
```


## Remarks

In fact, there are still some challenges in this project that we were unable to 
overcome, particularly regarding listening to the response. 
On one hand, the DNS protocol utilizes the UDP protocol, which does not involve 
formal "handshakes." 
Consequently, the client must continuously send "empty" messages to inquire 
whether there are any responses from the server, as the server does not 
spontaneously inform the client, even if, for instance, Google has already 
responded. 
On the other hand, our approach to transforming DNS packets into binary data 
does not strictly adhere to the standard DNS protocol, although it is very 
similar. 
Consequently, a genuine DNS server would not be able to interpret the data 
correctly. 
This issue could be easily rectified; 
however, given the complexities involved in implementing the server component, 
we made the decision to conclude the project in a simplified manner. 
Despite these challenges, the communication between the client and server, as 
well as the encoding/decoding process, have been successfully accomplished.