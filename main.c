/* main.c
*
* Created by Yan-Ting Justin Chen (yantingjc@student.unimelb.edu.au) on 17th May 2021
* This is my dns_svr main file that references packet_parser.c and packet_parser.h.
* The server code and the client code were created based on the workshop examples provided by
* the University Of Melbourne Computing Faculty.
*
* To run the program type: make clean then make -b
* ./dns_svr <IP Address> <Port Number>
* 
* Made up of 3 files including this one.
* -- main.c The main file that refers to the headerfile that refers to the two function files
* -- packet_parser.c includes the operations to parse the packet and combine uint8_t bytes to uint16_t.
* -- packet_parser.h includes all the function prototypes as well as struct prototypes
* 
*/
#define _POSIX_C_SOURCE 200112L
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <assert.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "packet_parser.h"



int main(int argc, char** argv) {
    
	int listen_fd, connect_fd, n, re, s;
	struct addrinfo hints, *res;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size;

    /*Return error if port for upstream not specified*/
	if (argc < 2) {
		fprintf(stderr, "ERROR, no port provided\n");
		exit(EXIT_FAILURE);
	}

	// Create address we're going to listen on (with given port number)
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;       // IPv4
	hints.ai_socktype = SOCK_STREAM; // TCP
	hints.ai_flags = AI_PASSIVE;     // for bind, listen, accept
    
    /* Listen on the specified port */
	s = getaddrinfo(NULL, LISTEN_PORT, &hints, &res);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}
    
    /* Create a socket and returns a fd that we will listen on, specifies IPV4/IPV6, UDP/TCP */
	listen_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (listen_fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	// Reuse port if possible
	re = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int)) < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	/* Bind address to the socket */
	if (bind(listen_fd, res->ai_addr, res->ai_addrlen) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(res);

	/* Listen to incoming connection requests, maximum of 10 at a time */
	if (listen(listen_fd, 10) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

 /* Main loop after setting up listening socket, this is where we connect to upstream and 
    respond to client with answer received from the upstream server */
    while(1){
        /* Gets connection file descriptor to communicate with client on */
        client_addr_size = sizeof client_addr;
        connect_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_addr_size);
        if (connect_fd < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        int packet_size_query = 0; // For returning packet size for writing to upstream and client
        int packet_size_response = 0; 
        int is_ipv6_query = 0; //1 if its ipv6, 0 if it isn't
        uint8_t *query_packet, *response_packet;

        /* This will parse the packet and manipulate parameters above for further processing
           the function also returns the full packet for writing purposes */
        FILE *out_file = fopen("dns_svr.log", "a");
        query_packet = packet_parser(connect_fd, &is_ipv6_query, &packet_size_query, out_file);
        fclose(out_file);
        

        /*If it is a valid ipv6_query connect and write to upstream server*/
        if(is_ipv6_query == 1){
            int upstream_fd, num, server_info;
            struct addrinfo upstream_hints, *upstream_servinfo,  *rp;

            if (argc < 3) {
                fprintf(stderr, "usage %s hostname port\n", argv[0]);
                exit(EXIT_FAILURE);
            }

            /* Create address to connect to upstream server */
            memset(&upstream_hints, 0, sizeof upstream_hints);
            upstream_hints.ai_family = AF_INET;
            upstream_hints.ai_socktype = SOCK_STREAM;

            /* Get the address info of the server with argv[1] and argv[2] input*/
            server_info = getaddrinfo(argv[1], argv[2], &upstream_hints, &upstream_servinfo);
            if (server_info != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(server_info));
                exit(EXIT_FAILURE);
            }

            /* Connect to first valid result */
            for (rp = upstream_servinfo; rp != NULL; rp = rp->ai_next) {
                upstream_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (upstream_fd == -1)
                    continue;

                if (connect(upstream_fd, rp->ai_addr, rp->ai_addrlen) != -1)
                    break; // success

                close(upstream_fd);
            }
            /* If connection to upstream failed print error message*/
            if (rp == NULL) {
                fprintf(stderr, "client: failed to connect\n");
                exit(EXIT_FAILURE);
            }
            freeaddrinfo(upstream_servinfo);

            /* Write query packet to upstream server */
            num = write(upstream_fd, query_packet, packet_size_query);
            if (num < 0) {
                perror("socket");
                exit(EXIT_FAILURE);
            }
            /* Read and parse the response packet from upstream server*/

            int is_ipv6_response = 0; // If response isn't IPV6 don't log
            FILE *out_file = fopen("dns_svr.log", "a");
            response_packet = packet_parser(upstream_fd, &is_ipv6_response, &packet_size_response, out_file);
            fclose(out_file);

            /* Write the response packet back to client who sent the query */
            n = write(connect_fd, response_packet, packet_size_response);
            if (n < 0) {
                perror("write");
                exit(EXIT_FAILURE);
            }
            
            close(upstream_fd);
        }
        /* Change the Response Code and QR to 1 for invalid requests */
        else if(is_ipv6_query == 0){
            query_packet[4] = (query_packet[4] & 00000000) | 129;
            query_packet[5] = (query_packet[5] & 00000000) | 132;
            /* Write back to the client with the header changed */
            n = write(connect_fd, query_packet, packet_size_query);
            if (n < 0) {
                perror("write");
                exit(EXIT_FAILURE);
            }
        }       
        close(connect_fd);
    }
    close(listen_fd);
	return 0;
}