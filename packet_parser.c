/* packet_parser.c
*
* Created by Yan-Ting Justin Chen (yantingjc@student.unimelb.edu.au) on 17th May 2021.
* This has the combining uint8_t to uint16_t function as well as the packet parsing function,
* it also contains the log formatting and printing.
*
*/

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

/*********************************************************************************/
/* This function combines two uint8 bytes in the right order so we dont need to 
  worry about endianness when calling this variable */

uint16_t combine_byte(uint8_t first_half, uint8_t second_half){
    uint16_t combination = ((uint16_t)first_half << 8) | second_half;
    return combination;
}

/*********************************************************************************/
/* This function reads the packet from the file descriptor passed to it and parses
   the packet, extracting information required for logs, printing the logs as well 
   as returning the original packet for the user to write the whole packet back. */

uint8_t *packet_parser(int fd, int *is_ipv6, int *total_packet_size, FILE *log_file){

    uint16_t packet_size;
    uint8_t packet_size_1, packet_size_2;

    /* Store the first 2 bytes to extract the packet_size */
    read(fd, &packet_size_1, 1);
    read(fd, &packet_size_2, 1);
    packet_size= combine_byte(packet_size_1, packet_size_2);
    
    /* Set the buffer to store the read in information */
    uint8_t *buffer;
    buffer = (uint8_t* )calloc(packet_size, sizeof(uint8_t));
    assert(buffer!=NULL);

    int z, v, b, g, j;
    int values_read = 0;
    int packet_size_remaining = packet_size;
    char processed_ipv6address[INET6_ADDRSTRLEN];

/* Case: Full packet isn't read/sent, will keep re-reading till size matches expected ammount */
    values_read = read(fd, buffer, packet_size);
    while(values_read != packet_size){
        packet_size_remaining = packet_size-values_read;
        values_read += read(fd, buffer+values_read, packet_size_remaining);
    }
    /* Allows program to return original packet with size header inside */
    uint8_t *original_packet = (uint8_t* )calloc(packet_size+2, sizeof(uint8_t));
    *total_packet_size = ((int)packet_size)+2;
    /* Stores the first 2 bytes read seperately then adjusts pointer for rest of packet */
    for(g=0; g<packet_size+2; g++){
        if(g==0){
            original_packet[g] = packet_size_1;
        }
        else if (g==1){
            original_packet[g] = packet_size_2;
        }
        else{
            original_packet[g] = buffer[g-2];
        }

    }

    header_t *header; 
    header = (header_t *)calloc(1, sizeof(header_t)); 
	assert(header!=NULL);
    
    uint16_t req_type, res_type;
    uint8_t *domainALL_ascii;
    uint8_t *ipv6_address_raw;
    ipv6_address_raw = (uint8_t *)calloc(17, sizeof(uint8_t));
    assert(ipv6_address_raw!=NULL);

    /* Variables for the main loop */
    int read_byte = 0;
    int stored_byte = 0;
    int iteration = 0;
    int labels_size = 0;
    int query_type;

    for(j=0;j<packet_size; j++){
        read_byte++;
        /* Reads in 2 bytes, stores the 2 bytes in struct */
        if(read_byte == 2 && stored_byte == 0){
            header->ID = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
            stored_byte++;
        }
        if(read_byte == 2 && stored_byte == 1){
            header->byte_2 = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
            stored_byte++;

            if(buffer[j-1] & 10000000){ //If the packet is a response 
                query_type = 1; 
            } /* Query = 0, Response = 1 */
            else{ //If the packet is a request 
                query_type = 0;
            }
        }
        if(read_byte == 2 && stored_byte == 2){
            header->QDCOUNT = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
            stored_byte++;
        }
        if(read_byte == 2 && stored_byte == 3){
            header->ANCOUNT = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
            stored_byte++;
        }
        if(read_byte == 2 && stored_byte == 4){
            header->NSCOUNT = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
            stored_byte++;
        }
        if(read_byte == 2 && stored_byte == 5){
            header->ARCOUNT = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
            stored_byte++;
        }
        /* Stores the labels by reading until end of labels */
        if(buffer[j]== 0 && stored_byte == 6 ){ 
            stored_byte++;
            if(iteration == 0){ //first time in this loop calloc otherwise don't
                domainALL_ascii = (uint8_t* )calloc(read_byte, sizeof(uint8_t));
                labels_size = read_byte-1; 
                iteration = 1;
            }
            b=0;
            for(v=(j-read_byte+1); v<j; v++){
                domainALL_ascii[b] = buffer[v];
                b++;
            }
            domainALL_ascii[labels_size] = '\0';
            read_byte = 0;
        }
        /* Store request type for log logic */
        if(read_byte == 2 && stored_byte == 7 ){
            req_type = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
            stored_byte++;
        }
        /* Extract IP here check for query type = response */
        if(read_byte == 6 && stored_byte == 8 && query_type == 1){ 
            res_type = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
            stored_byte++;
        }
        /*Since IPV6 addresses are 16 bytes long just extract 8-16 read bytes*/
        if(read_byte == 24 && stored_byte == 9 && query_type ==1){
            stored_byte++;
            for(g=0; g<16; g++){
                ipv6_address_raw[g] = buffer[j-16+g+1];

            }
            ipv6_address_raw[16] = '\0';
        }
    }
    char domain_name[labels_size];
    int next_label_location;
    int curr_size;
    int copied_values =0;
    /* This function here takes the labels and formats it correctly for logs. */
    for(z=0; z<labels_size; z++){
        if(z==0){
            curr_size = domainALL_ascii[z];
            next_label_location = z+curr_size+1;
            continue;
        }
        if(z==next_label_location){
            domain_name[copied_values] = '.';
            copied_values++;
            next_label_location += domainALL_ascii[z];
            next_label_location +=1;
            
        }
        else if (z!=next_label_location){
            domain_name[copied_values] = domainALL_ascii[z];
            copied_values++;
        }
    }
    domain_name[copied_values] = '\0';

    
    
    /* Function to print logs, time function adapted from website:
      https://www.cplusplus.com/reference/ctime/strftime/ */
    time_t rawtime;
    struct tm *info;
    char time_buffer[80];
    time( &rawtime );
    info = localtime( &rawtime );
    strftime(time_buffer,80,"%FT%T%z", info);

    /* Print different logs depending on Request/Response or IPV6/Not IPV6 etc. */
    if(query_type == 0){ //If it is a request
        fprintf(log_file, "%s requested %s\n", time_buffer, domain_name);
        fflush(log_file);

         /* Check if it's IPV6 */
        if(req_type == 28){
            *is_ipv6 = 1;
        }
        if (req_type != 28){
            fprintf(log_file,"%s unimplemented request\n", time_buffer);
            fflush(log_file);
            *is_ipv6 = 0;
        }
    }
    if(query_type == 1 && res_type == 28){ //if it is a response
        *is_ipv6 =1;
        /* Converts the raw address to a properly formatted ipv6 address */
        if (inet_ntop(AF_INET6, ipv6_address_raw, processed_ipv6address, sizeof(processed_ipv6address)) != NULL){
            fprintf(log_file, "%s %s is at %s\n", time_buffer, domain_name, processed_ipv6address);
            fflush(log_file);
        }
        else{
            perror("inet_ntop");
            exit(EXIT_FAILURE);
        }      
    }
    /* If response is not AAAA type then don't print any logs*/
    else if(query_type == 1 && res_type != 28) {
        *is_ipv6 = 0;
    }
    return original_packet;
}
