//
//  server.c
//  custom_network
//
//  Copyright (c) 2015 Peera Yoodee. All rights reserved.
//

#include "server.h"
#define SOCKET_RCVBUFFER 212992     // net.core.rmem_max
#define SOCKET_SNDBUFFER 212992     // net.core.wmem_max
int padding1 = RSA_PKCS1_PADDING;
RSA * createRSA1(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
    return rsa;
}

int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA1(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding1);
    return result;
}
void server(uint16_t src, const char *keystoredir, int num_interfaces, struct interface *interface) {
    
    char *privatekeyfile, *publickeyfile;
    char genrsa_command[strlen(keystoredir) * 10];
    FILE *file_privatekey, *file_publickey, *file;
    char name[5];
    strcpy(name, interface->interface_name);
    uint16_t file_public_size,file_private_size;
    uchar_t  *packet;
    packet = (uchar_t *) malloc(MTU);
    memset(packet, 0, 1500);
    unsigned char* encrypted;
    unsigned char* decrypted;
    unsigned char *buffer_publickey,*buffer_privatekey, buffer[1518],buffer_send[1518];
//    size_t header_length = sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_linkkeyexchange);
    //struct layer4_linkkeyexchange *packet_l4 = (struct layer4_linkkeyexchange *) (packet + sizeof(struct layer2) + sizeof(struct layer3));
    struct layer4_linkkeyexchange *buffer_l4 = (struct layer4_linkkeyexchange*) (buffer + sizeof(struct layer2) + sizeof(struct layer3)); 
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

    //Read private key
    file_privatekey = fopen(privatekeyfile, "rb");

    // Get the size of the private key file
    fseeko(file_privatekey, 0 , SEEK_END);
    file_private_size = (uint16_t) ftello(file_privatekey);
    fseeko(file_privatekey, 0 , SEEK_SET);

    buffer_privatekey = (unsigned char *) malloc(file_private_size);

    // Read the private key file into buffer
    if (!fread(buffer_privatekey, file_private_size, 1, file_privatekey) == file_private_size) {
        fprintf(stderr, "Error: error reading private key file");
        return;
    }
    
    for (i=0; i<file_private_size; i++) {
        printf("%c", buffer_privatekey[i]);
    }
    
    // Initialize socket buffer
    memset(buffer, 0, sizeof(buffer));
    
      //Prepare interface and socket
      sa.sll_family = PF_PACKET;
      sa.sll_ifindex = interface->interface_index; 
      sa.sll_halen = 0;
      sa.sll_protocol = htons(ETH_P_ALL);
      sa.sll_hatype = 0;
      sa.sll_pkttype = 0;
    
      mreq.mr_ifindex = interface->interface_index;
      mreq.mr_type = PACKET_MR_PROMISC;
      mreq.mr_alen = 0;
    
      // Set filter to socket
      prog_filter.len = 8;
      prog_filter.filter = incoming_filter;

      int sockfd,recvlen;
       // Create socket
    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        fprintf(stderr, "Error: cannot create raw socket in init_receiver()\n");
        exit(1);
    }
    
    // Set Socket Options
    int so_sndbuf_size = SOCKET_SNDBUFFER;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &so_sndbuf_size, sizeof(so_sndbuf_size)) < 0) {
        fprintf(stderr, "Error: cannot set SO_SNDBUF in init_receiver()\n");
        exit(2);
    }
    int so_rcvbuf_size = SOCKET_RCVBUFFER;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &so_rcvbuf_size, sizeof(so_rcvbuf_size)) < 0) {
        fprintf(stderr, "Error: cannot set SO_RCVBUF in init_receiver()\n");
        exit(2);
    }
    
    // Set Promiscuous mode and filter
    if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        fprintf(stderr, "Error: cannot set PACKET_ADD_MEMBERSHIP + PACKET_MR_PROMISC in init_receiver()\n");
        exit(2);
    }
/*    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &prog_filter, sizeof(prog_filter)) < 0)
    {
        fprintf(stderr, "Error: cannot set SO_ATTACH_FILTER in init_receiver()\n");
        exit(2);
    }*/

    // Bind socket
    if(bind(sockfd ,(struct sockaddr *) &sa, sizeof(sa)) <0) {
        fprintf(stderr, "Error bind raw socket failed in init_receiver()\n");
        exit(3);
    }
   struct layer2 *l2;
   struct layer3 *l3;
   l2 = (struct layer2 *) buffer_send;
   l3 = (struct layer3 *) (buffer_send + sizeof(struct layer2));

    while (1) {
        recvlen = recv(sockfd, buffer, 1500, 0);
        if ((recvlen != -1UL)) {
           l2->original_source_addr = htons(src);
           l3->ttl =0;
           memset(l3->source_routing, 0x00, MAX_HOPS);
           l3->type = TYPE_LINKKEYEXCHG;
	   struct layer4_linkkeyexchange_pubkey *buffer_l4_pubkey = (struct layer4_linkkeyexchange_pubkey*)(buffer_send+ sizeof(struct layer2) + sizeof(struct layer3));
	   buffer_l4_pubkey->type =1 ;
 	   buffer_l4_pubkey->exchgid =  buffer_l4->exchgid;
	   buffer_l4_pubkey->pubkeylen = htons(file_public_size);
	   memcpy(buffer_send+ sizeof(struct layer2) + sizeof(struct layer3)+sizeof(struct layer4_linkkeyexchange_pubkey),buffer_publickey,file_public_size);
	   send(sockfd, buffer_send, sizeof(struct layer2) + sizeof(struct layer3)+sizeof(struct layer4_linkkeyexchange_pubkey)+file_public_size, 0 );
            }
 	recvlen = recv(sockfd, buffer, 1500, 0);
	struct layer4_linkkeyexchange_propose *bufferpub = (struct layer4_linkkeyexchange_propose*)(buffer + sizeof(struct layer2) + sizeof(struct layer3));
        
	if ((recvlen != -1UL && bufferpub->type == 2)) {
		int enc_len = bufferpub->enclinkkeylen;
		int link_len = bufferpub->linkkeylen;
		encrypted = (unsigned char*)malloc(sizeof(unsigned char *)*ntohs(bufferpub->enclinkkeylen));
	        decrypted = (unsigned char*)malloc(sizeof(unsigned char *)*ntohs(bufferpub->linkkeylen));
                memset(encrypted,0x00,enc_len);
		memset(decrypted,0x00,link_len);
                memcpy(encrypted, buffer+sizeof(struct layer2) + sizeof(struct layer3)+sizeof(struct layer4_linkkeyexchange_propose),enc_len);
		int decrypted_length = private_decrypt(encrypted,enc_len,buffer_privatekey, decrypted);
		if(decrypted_length == -1) {
			printf("Private Decrypt failed ");
			exit(0);
		}
		file = fopen(name, "w");
                fwrite(decrypted,1,decrypted_length,file);
		fclose(file);
		memset(buffer_send,0x00,MTU);
		l2->original_source_addr = htons(src);
		l3->ttl =0;
	        memset(l3->source_routing, 0x00, MAX_HOPS);
           	l3->type = TYPE_LINKKEYEXCHG;
		struct layer4_linkkeyexchange *buffer_l4_ack = (struct layer4_linkkeyexchange*) (buffer_send + sizeof(struct layer2) + sizeof(struct layer3));
		buffer_l4_ack->type = 3;
                buffer_l4_ack->exchgid = 1;
		char str[4] = "ack";
		memcpy(buffer_send + sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_linkkeyexchange),str, strlen(str));
		send(sockfd, buffer_send, sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_linkkeyexchange) + strlen(str), 0 );
		printf("Bootstrap Process Complete\n"); 

	} 
    }
}
