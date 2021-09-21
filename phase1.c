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



int main(int argc, char* argv[]) {
    int fd =0;
    // This is in 3400 need to ntohs it
    uint16_t packet_size;
    //fd = open(argv[2], O_RDONLY);
    FILE *log_file = fopen("dns_svr.log", "a");
    /*printf("argc value is : %d\n", argc);*/

    //int bytes_read = read(fd, &packet_size, 2);
    read(fd, &packet_size, 2);
    //printf("%d\n", (int)read(fd, packet_size, 2));
    //printf("Bytes Read: %d \n", bytes_read);
    //printf("%04x\n", ntohs(packet_size));
    
    char processed_ipv6address[INET6_ADDRSTRLEN];
    int j;
    uint8_t *buffer;
    buffer = (uint8_t* )calloc(ntohs(packet_size), sizeof(uint8_t));
    assert(buffer!=NULL);
    read(fd, buffer, ntohs(packet_size));
    //printf("Hi: %d\n", (int)read(fd, buffer, ntohs(packet_size)));


    int read_byte = 0;
    int stored_byte = 0;
    header_t *header;
    header = (header_t *)calloc(1, sizeof(header_t)); 
	assert(header!=NULL);

    //Counter might be counterintuitive because im doing 2 bytes for some and 1 for some.
    int z, v, b, g;

    uint16_t req_type, res_type;
    uint8_t *domainALL_ascii;
    uint8_t *ipv6_address_raw;
    ipv6_address_raw = (uint8_t *)calloc(17, sizeof(uint8_t));
    assert(ipv6_address_raw!=NULL);
    int iteration = 0;
    int labels_size = 0;
    int query_type;
    int ipv_loop = 0;

    for(j=0;j<ntohs(packet_size); j++){
        read_byte++;
        if(read_byte == 2 && stored_byte == 0){
            stored_byte++;
            header->ID = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
        }
        if(read_byte == 2 && stored_byte == 1){
            stored_byte++;
            header->byte_2 = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
            if(buffer[j-1] & 10000000){ //If the packet is a response
                //printf("True\n");
                query_type = 1;
            }
            else{ //If the packet is a request
                //printf("False\n");
                query_type = 0;
            }
        }
        if(read_byte == 2 && stored_byte == 2){
            stored_byte++;
            header->QDCOUNT = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
        }
        if(read_byte == 2 && stored_byte == 3){
            stored_byte++;
            header->ANCOUNT = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
        }
        if(read_byte == 2 && stored_byte == 4){
            stored_byte++;
            header->NSCOUNT = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
        }
        if(read_byte == 2 && stored_byte == 5){
            stored_byte++;
            header->ARCOUNT = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
        }

        if(buffer[j]!= 0 && stored_byte == 6){
            //printf("This is the read byte: %02x\n", buffer[j]);
            
        }
        else if(buffer[j]== 0 && stored_byte == 6 ){ //End of the labels 
            stored_byte++;
            //printf("Reached the null byte\n");
            if(iteration == 0){ //first time in this loop calloc otherwise don't
                domainALL_ascii = (uint8_t* )calloc(read_byte, sizeof(uint8_t));
                labels_size = read_byte-1;
                //printf("This is read_byte: %d\n", read_byte);
                //printf("This is the labels_size %d\n", labels_size);
                iteration = 1;
            }
            b=0;
            for(v=(j-read_byte+1); v<j; v++){
                //printf("This is the read byte: %02x\n", buffer[v]);
                domainALL_ascii[b] = buffer[v];
                b++;
            }
            domainALL_ascii[labels_size] = '\0';
            read_byte = 0;
            //printf("This is stored byte %d and the b value %d\n", stored_byte, b);
        }
        
        if(read_byte == 2 && stored_byte == 7){
            stored_byte++;
            req_type = combine_byte(buffer[j-1], buffer[j]);
            read_byte = 0;
        }
        if(read_byte == 6 && stored_byte == 8 && query_type ==1){ //extract ip~~
            stored_byte++;
            res_type = combine_byte(buffer[j-1], buffer[j]);
            read_byte=0;
        }
        /*Since IPV6 addresses are 16 bytes long just extract 8-16 read bytes*/
        if(read_byte == 24 && stored_byte == 9 && query_type ==1){
            stored_byte++;
            //int h=0;
            for(g=0; g<16; g++){
                ipv6_address_raw[g] = buffer[j-16+g+1];
                //printf("Adding: %02x to ", buffer[j-16+g+1]);
                //printf("This ipv6_address_raw[%d] value: %02x\n", g, ipv6_address_raw[g]);
                ipv_loop++;
                /*
                h++;
                if(ipv_loop == 2){
                    //printf("Entering loop\n");
                    ipv6_address_raw[h] = ':';
                    h++;
                    ipv_loop = 0;
                }
                */
            }
            ipv6_address_raw[16] = '\0';
        }
    }
    //printf("This is the query type: %d\n", query_type);
    //printf("This is the domain");
    //printf("We've reached the end\n");
    //printf("Request Type:  %04x\nResponse Type: %04x\n", req_type, res_type);
    //printf("IPV6 address is ");
    /*
    unsigned char ip_6addr[16];
    for(g=0; g<16; g++){
        printf("%02x ", ipv6_address_raw[g]);
        ip_6addr[g] = ipv6_address_raw[g];
    }
    printf("\nAddress is: %s\n", ipv6_address_raw);
    printf("IPV6 addr in unsigned char form: %s\n", ip_6addr);
    */

    /*printf("Header Stored Bytes: %04x  ||  %04x  ||  %04x  ||  %04x  ||  %04x  ||  %04x\n", header->ID, header->byte_2, header->QDCOUNT, 
                                                                                    header->ANCOUNT, header->NSCOUNT, header ->ARCOUNT);
    */
    


   
    char domain_name[labels_size-1];
    int next_label_location;
    int curr_size;
    int copied_values =0;

    for(z=0; z<labels_size; z++){
        if(z==0){
            curr_size = domainALL_ascii[z];
            next_label_location = z+curr_size+1;
            continue;
        }
        if(z==next_label_location){
            //printf("This is the label location rn kekekekoijdoiaj COCK %d\n", z);
            domain_name[copied_values] = '.';
            copied_values++;
            //printf("This is the Domain_name[%d] value: %c\n",copied_values-1, domain_name[copied_values-1]);
            //printf("This is the value: %x\n",domainALL_ascii[z]);
            next_label_location += domainALL_ascii[z];
            next_label_location +=1;
            //printf("This is the next label location %d \n", next_label_location);
            
        }
        else if (z!=next_label_location){
            domain_name[copied_values] = domainALL_ascii[z];
            copied_values++;
            //printf("storing this %c\n", domainALL_ascii[z]);
            //printf("This is z value %d\n", z);
            //printf("This is the Domain_name[%d] value: %c\n",copied_values-1, domain_name[copied_values-1]);
        }
        //printf("Domain name: %s\n", domain_name);
    }
    domain_name[copied_values] = '\0';

    //printf("This is the domain: %s\n", domain_name);
    
    
    /*
    if (inet_ntop(AF_INET6, ipv6_address_raw, processed_ipv6address, sizeof(processed_ipv6address)) != NULL)
      printf("inet6 addr: %s\n", processed_ipv6address);
    else {
      perror("inet_ntop");
      exit(EXIT_FAILURE);
   }
    */
    /*Function to print logs*/
    struct in6_addr ;
    time_t rawtime;
    struct tm *info;
    char time_buffer[80];
    time( &rawtime );
    info = localtime( &rawtime );
    
    strftime(time_buffer,80,"%FT%T%z", info);
    if(query_type == 0){ //If it is a request
        fprintf(log_file, "%s requested %s\n", time_buffer, domain_name);

         /* Check if it's IPV6 */
        if (req_type != 28){
            fprintf(log_file,"%s unimplemented request\n", time_buffer);
        }
    }
    if(query_type == 1 && res_type == 28){ //if it is a response
        inet_ntop(AF_INET6, ipv6_address_raw, processed_ipv6address, sizeof(processed_ipv6address));
        fprintf(log_file, "%s %s is at %s\n", time_buffer, domain_name, processed_ipv6address);

    }
    
    

    fclose(log_file);




    return 0;
}

