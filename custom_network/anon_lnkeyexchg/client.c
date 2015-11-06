//
//  client.c
//  custom_network
//
//  Copyright (c) 2015 Peera Yoodee. All rights reserved.
//

#include "client.h"
#define ENC_BUF_LEN 256
int padding = RSA_PKCS1_PADDING;
RSA * createRSA(unsigned char * key,int public)
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

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}



void client(uint16_t src, const char *keystoredir, int num_interfaces, struct interface *interface) {
	int sockfd;
	unsigned char buffer_udp[MTU];
	unsigned char *buffer=buffer_udp;
	unsigned char *recvbuffer = (unsigned char*)malloc (MTU*sizeof(unsigned char));
	unsigned char *publickey;
	unsigned char symkey[32];
	char *symkeyfile;
	symkeyfile  = (char *) malloc(strlen(keystoredir) + strlen(interface->interface_name)+ 1);
	strcpy(symkeyfile, keystoredir);
	strcat(symkeyfile, interface->interface_name);
	//unsigned char  encrypted[MTU]={};
	unsigned char encrypted_key[ENC_BUF_LEN]={};
	//AES_KEY enc_key;
    	memset(recvbuffer,0x00,MTU);
    	memset(buffer,0x00,MTU);
	struct layer2 *l2;
    	struct layer3 *l3;
    	struct layer4_linkkeyexchange *l4;
    	struct layer4_linkkeyexchange_propose *l4_pub_propose;
	struct layer4_linkkeyexchange_pubkey *l4_pub;
    	struct sockaddr_ll sa_in;
    	size_t header_size;
    	header_size = sizeof(struct layer2) + sizeof(struct layer3) + sizeof(struct layer4_linkkeyexchange);
    	l2 = (struct layer2 *) buffer;
    	l3 = (struct layer3 *) (buffer + sizeof(struct layer2));
    	l4 = (struct layer4_linkkeyexchange *) (buffer + sizeof(struct layer2) + sizeof(struct layer3));
	/*source address*/
     	l2->original_source_addr = htons(src);
    	// Read Path
     	l3->ttl =0;
     	memset(l3->source_routing, 0x00, MAX_HOPS);
     	l3->type = TYPE_LINKKEYEXCHG;
	l4->type = 0;
	l4->exchgid = 1;
	char hello[6] = "Hello";
	memcpy(buffer + header_size,hello, strlen(hello));
	sa_in.sll_family = PF_PACKET;
    	sa_in.sll_ifindex = interface->interface_index;
    	sa_in.sll_halen = 0;
   	sa_in.sll_protocol = htons(ETH_P_ALL);
    	sa_in.sll_hatype = 0;
    	sa_in.sll_pkttype = 0;
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
       		fprintf(stderr, "Error: cannot create raw socket in init_sender()\n");
        	exit(1);
    	}
        struct ifreq ifopts;
        strncpy(ifopts.ifr_name, interface->interface_name, IFNAMSIZ-1);
    	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
    	ifopts.ifr_flags |= IFF_PROMISC;
    	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
    	int optval;
    	optval = 1;
    	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
    	}
 
    	if (bind(sockfd, (struct sockaddr *)&sa_in, sizeof(sa_in)) != 0) {
        	fprintf(stderr, "Cannot bind to raw socket for outgoing interface\n");
   	}
   	send(sockfd, buffer, MTU, 0 ); 
	size_t recvlen;
	recvlen = recv(sockfd, recvbuffer, MTU, 0);
	if (recvlen != -1UL) {
	    l4_pub = (struct layer4_linkkeyexchange_pubkey *) (recvbuffer + sizeof(struct layer2) + sizeof(struct layer3));
	    printf("type layer 4 %d ",l4_pub->type);
	    if(l4_pub->type==1){
			publickey = (unsigned char*)malloc(sizeof(unsigned char *)*ntohs(l4_pub->pubkeylen));		
			printf("layer 4 pubkey length %d ",ntohs(l4_pub->pubkeylen));
			memset(publickey,0x00,ntohs(l4_pub->pubkeylen));
	    		header_size = sizeof(struct layer2) + sizeof(struct layer3)+sizeof(struct layer4_linkkeyexchange_pubkey);
			memcpy(publickey, recvbuffer+header_size,ntohs(l4_pub->pubkeylen));
                	fprintf(stdout, "[DEBUG] Recv: ACK 0x%.6llx\n", publickey);
           		memset(buffer,0x00,MTU);
			l2->original_source_addr = htons(src);
		        // Read Path
        		l3->ttl =0;
        		memset(l3->source_routing, 0x00, MAX_HOPS);
			l3->type = TYPE_LINKKEYEXCHG;
			l4_pub_propose = (struct layer4_linkkeyexchange_propose *) (buffer + sizeof(struct layer2) + sizeof(struct layer3));
			l4_pub_propose->type = 2;
        		l4_pub_propose->exchgid = 1;
			RAND_bytes(symkey,32);
			
			l4_pub_propose->linkkeylen = 32;
			int encrypted_length= public_encrypt(symkey,32,publickey,encrypted_key); 
			l4_pub_propose->enclinkkeylen =  encrypted_length;
			memcpy(buffer+ sizeof(struct layer2) + sizeof(struct layer3)+sizeof(struct layer4_linkkeyexchange_propose),encrypted_key,encrypted_length);
			size_t enc_pkt_len = sizeof(struct layer2) + sizeof(struct layer3)+sizeof(struct layer4_linkkeyexchange_propose)+encrypted_length;  
			send(sockfd, buffer , enc_pkt_len, 0 );
			
			
	   }
	    
	}
        else {
            #ifdef _DEBUG
            fprintf(stdout, "[DEBUG] Timeout!\n");
            #endif
        }
}
