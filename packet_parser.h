/*
*
* Created by Yan-Ting Justin Chen (yantingjc@student.unimelb.edu.au) on 17th May 2021.
* This file contains structure and function prototypes as well as definitions.
*
*/

#define LISTEN_PORT "8053"
#define TRUE 1;
#define FALSE 0;



/*****************************************************************************/
/* Struct Prototypes */

typedef struct {
	uint16_t ID;
    uint16_t byte_2; 
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
} header_t;


/*****************************************************************************/
/* Function Prototypes */

uint16_t combine_byte(uint8_t first_half, uint8_t second_half);
uint8_t *packet_parser(int fd, int *is_ipv6, int *total_packet_size, FILE *log_file);

/*****************************************************************************/