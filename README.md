# DNS Server
**Version 1.0.0**

A Simple DNS proxy server for with logging that only accepts IPv6 packets, written in C.

- It will listen for DNS requests in binary ".raw" packets for IPv6 addresses over **TCP**, on specified port with sockets.
- Program parses the packet recognizing its a request and creates a connection to an upstream server through socket programming and forwards it to another DNS server.
- Program recieves the packet back and it recognizes its a response and it forwards it back to the user that requested the packet.
- After each request is completed it logs the server events in the file "./dns_svr.log"

Notice:
- Uses POSIX library, so it won't run on windows (need WSL/Ubuntu)
- Does not cache recent queries, and isn't multithreaded so it blocks when forwarding each request

## How to run program

Compile using the command:
```
make
```
Start the server with this command:
```
./dns_svr <hostname> <port>
```

## Example of running
We can use Google's public DNS with the command:
```
./dns_svr 8.8.8.8 53
```
We can use `dig` on a DNS client, in this example we will request the AAAA (IPv6) address of `cloudflare.com` through TCP, from the local server 0.0.0.0 on port 8053.
```
dig +tcp @0.0.0.0 -p 8053 AAAA cloudflare.com
```

It will put in the logfile `./dns_svr.log`  the request and the reply with timestamps.