//
//  server.c
//  custom_network
//
//  Copyright (c) 2015 Peera Yoodee. All rights reserved.
//

#include "server.h"

void server(uint16_t src, const char *keystoredir, int num_interfaces, struct interface *interface) {
    
    char *privatekeyfile, *publickeyfile;
    char genrsa_command[strlen(keystoredir) * 10];
    FILE *file_privatekey, *file_publickey;
    
    uint16_t file_public_size;
    
    unsigned char *buffer_publickey, buffer[1518];
    
    // Socket filter
    struct sockaddr_ll sa;
    struct packet_mreq mreq;
    struct sock_fprog prog_filter;
    struct sock_filter incoming_filter[] = {
        { 0x30, 0, 0, 0x00000002 }, // Position of Layer3:Type
        { 0x15, 0, 4, 0x00000002 }, //   2 means Link Key Exchange Packet
        { 0x30, 0, 0, 0x00000008 }, // Position of Layer4:LinkKeyExchange:Type
        { 0x15, 1, 0, 0x00000000 }, //   0 means Link Key Exchange Request Packet  OR
        { 0x15, 0, 1, 0x00000002 }, //   2 means Proposed Link Key
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    incoming_filter[2].k = (uint32_t)(sizeof(struct layer2) + sizeof(struct layer3)); // Set position of Layer4:LinkKeyExchange:Type
    
    
    // Construct the full path to public/private key file
    privatekeyfile = (char *) malloc(strlen(keystoredir) + strlen("/private.pem") + 1);
    publickeyfile  = (char *) malloc(strlen(keystoredir) + strlen("/public.pem") + 1);
    strcpy(privatekeyfile, keystoredir);
    strcat(privatekeyfile, "/private.pem");
    strcpy(publickeyfile, keystoredir);
    strcat(publickeyfile, "/public.pem");
    
    // Read private key
    while (!(file_privatekey = fopen(privatekeyfile, "rb"))) {
        
        printf("RSA private key does not exist\n");
        
        // Construct a shell command for generating an RSA public/private key pair
        sprintf(genrsa_command,
            "/usr/bin/openssl genrsa -out %s 2048 && /usr/bin/openssl rsa -in %s -outform PEM -pubout -out %s",
            privatekeyfile, privatekeyfile, publickeyfile
        );
        
        // Execute the shell command
        if (system(genrsa_command) != 0) {
            fprintf(stderr, "Error: could not generate an RSA public/private key pair");
            return;
        }
    }
    
    // Read public key
    file_publickey = fopen(publickeyfile, "rb");
    
    // Get the size of the public key file
    fseeko(file_publickey, 0 , SEEK_END);
    file_public_size = (uint16_t) ftello(file_publickey);
    fseeko(file_publickey, 0 , SEEK_SET);
    
    buffer_publickey = (unsigned char *) malloc(file_public_size);
    
    // Read the public key file into buffer
    if (!fread(buffer_publickey, file_public_size, 1, file_publickey) == file_public_size) {
        fprintf(stderr, "Error: error reading public key file");
        return;
    }
    
    int i;
    for (i=0; i<file_public_size; i++) {
        printf("%c", buffer_publickey[i]);
    }
    
    printf("%u", file_public_size);
    
    // Initialize socket buffer
    memset(buffer, 0, sizeof(buffer));
    
    // Prepare interface and socket
//    sa.sll_family = PF_PACKET;
//    sa.sll_ifindex = output_interface->interface_index;
//    sa.sll_halen = 0;
//    sa.sll_protocol = htons(ETH_P_ALL);
//    sa.sll_hatype = 0;
//    sa.sll_pkttype = 0;
//    
//    mreq.mr_ifindex = output_interface->interface_index;
//    mreq.mr_type = PACKET_MR_PROMISC;
//    mreq.mr_alen = 0;
//    
//    // Set filter to socket
//    prog_filter.len = 8;
//    prog_filter.filter = incoming_filter;
}
