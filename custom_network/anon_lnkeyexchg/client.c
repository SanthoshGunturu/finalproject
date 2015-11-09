//
//  client.c
//  custom_network
//
//  Created by Peera Yoodee on 11/5/15.
//

#include "client.h"

void client(uint16_t src, const char *keystoredir, int num_interfaces, struct interface **interfaces) {
    
    int i, j, encrypted_linkkey_length;
    
    struct interface *interface = *interfaces;
    
    char linkkeyfile[strlen(keystoredir) + 20];
    FILE *file_linkkey;
    
    char hello[6] = "Hello";
    unsigned char buffer_recv[MTU], buffer_send[MTU], *publickey, linkkey[LINKKEY_LENGTH], encrypted_linkkey[RSA_KEY_LENGTH_BIT/8];
    
    struct layer2 *l2;
    struct layer3 *l3;
    struct layer4_linkkeyexchange *l4;
    struct layer4_linkkeyexchange_pubkey *l4_pubkey;
    struct layer4_linkkeyexchange_propose *l4_propose;
    size_t header_length;
    
    // Socket and its filter
    struct timeval timeout;
    ssize_t recvlen;
    int sockfd[num_interfaces];
    struct sockaddr_ll sa[num_interfaces];
    struct packet_mreq mreq[num_interfaces];
    struct sock_fprog prog_filter;
    struct sock_filter incoming_filter[] = {    // ether[2]=2 and (ether[8]=1 or ether[8]=3) and !(ether[0]=0xff and ether[1]=0xee)
        { 0x30, 0, 0, 0x00000002 }, // Position of Layer3:Type
        { 0x15, 0, 8, 0x00000002 }, //   2 means Link Key Exchange Packet
        { 0x30, 0, 0, 0x00000008 }, // Position of Layer4:LinkKeyExchange:Type
        { 0x15, 1, 0, 0x00000001 }, //   1 means Server Public Key Response  OR
        { 0x15, 0, 5, 0x00000003 }, //   3 means Agree
        { 0x30, 0, 0, 0x00000000 },
        { 0x15, 0, 2, 0x000000ff }, // value of ether[0]
        { 0x30, 0, 0, 0x00000001 },
        { 0x15, 1, 0, 0x000000ee }, // value of ether[1]
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    };
    incoming_filter[2].k = (uint32_t)(sizeof(struct layer2) + sizeof(struct layer3)); // Set position of Layer4:LinkKeyExchange:Type
    incoming_filter[6].k = (uint32_t)((src>>8) & 0xff);     // Filter out all outgoing messages
    incoming_filter[8].k = (uint32_t)(src & 0xff);
    prog_filter.len = 11;
    prog_filter.filter = incoming_filter;
    
    timeout.tv_sec = 1;
    timeout.tv_usec = 0L;
    
    l2 = (struct layer2 *) buffer_send;
    l3 = (struct layer3 *) (buffer_send + sizeof(struct layer2));
    l4 = (struct layer4_linkkeyexchange *) (buffer_send + sizeof(struct layer2) + sizeof(struct layer3));
    l4_pubkey  = (struct layer4_linkkeyexchange_pubkey *) (buffer_send + sizeof(struct layer2) + sizeof(struct layer3));
    l4_propose = (struct layer4_linkkeyexchange_propose *) (buffer_send + sizeof(struct layer2) + sizeof(struct layer3));
    header_length = sizeof(struct layer2) + sizeof(struct layer3);
    
    // Initialize socket buffer
    memset(buffer_recv, 0, sizeof(buffer_recv));
    memset(buffer_send, 0, sizeof(buffer_send));
    
    // Initialize packet header
    l3->type = TYPE_LINKKEYEXCHG;
    l3->ttl = 0;
    
    
    // Prepare interface and socket
    for (i=0; i<num_interfaces; i++) {
        sa[i].sll_family = PF_PACKET;
        sa[i].sll_ifindex = interface[i].interface_index;
        sa[i].sll_halen = 0;
        sa[i].sll_protocol = htons(ETH_P_ALL);
        sa[i].sll_hatype = 0;
        sa[i].sll_pkttype = 0;
        mreq[i].mr_ifindex = interface[i].interface_index;
        mreq[i].mr_type = PACKET_MR_PROMISC;
        mreq[i].mr_alen = 0;
        
        // Create Socket
        if ((sockfd[i] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
            fprintf(stderr, "Error: cannot create raw socket in server()\n");
            exit(1);
        }
        
        // Set Promiscuous mode and filter
        if (setsockopt(sockfd[i], SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq[i], sizeof(mreq[i])) < 0) {
            fprintf(stderr, "Error: cannot set PACKET_ADD_MEMBERSHIP + PACKET_MR_PROMISC in server()\n");
            exit(2);
        }
        if (setsockopt(sockfd[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog_filter, sizeof(prog_filter)) < 0) {
            fprintf(stderr, "Error: cannot set SO_ATTACH_FILTER in server()\n");
            exit(2);
        }
        
        // Set receive timeout to allow retries
        if (setsockopt(sockfd[i], SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&timeout, sizeof(struct timeval)) < 0) {
            fprintf(stderr, "Error: cannot set SO_RCVTIMEO in server()\n");
            exit(2);
        }
        
        // Bind socket to interface
        if(bind(sockfd[i] ,(struct sockaddr *) &sa[i], sizeof(sa[i])) <0) {
            fprintf(stderr, "Error bind raw socket failed in server()\n");
            exit(3);
        }
    }
    

    
    for (i=0; i<num_interfaces; i++) {
        
        // Generate random exchange id to use for a single key exchange
        RAND_bytes(&l4->exchgid, sizeof(l4->exchgid));
        
        // Construct a 'Link Key Exchange Request' packet
        l2->original_source_addr = htons(src);
        l4->type = TYPE_LINKKEYEXCHANGE_REQUEST;
        memcpy(buffer_send + header_length + sizeof(struct layer4_linkkeyexchange), hello, strlen(hello));
        
        while(1) {
            
            send(sockfd[i], buffer_send, header_length + sizeof(struct layer4_linkkeyexchange) + strlen(hello), 0);
            printf("Send Request exchangeid=0x%.2x\n", l4->exchgid);
            
            recvlen = recv(sockfd[i], buffer_send, MTU, 0);
            if ((recvlen != -1) && (l4->type == TYPE_LINKKEYEXCHANGE_PUBKEY)) {
                printf("Recv PublicKey from host=%d exchangeid=0x%.2x\n", ntohs(l2->original_source_addr), l4->exchgid);
                break;
            }
        }
        
        publickey = buffer_send + header_length + sizeof(struct layer4_linkkeyexchange_pubkey);
        
        // Print public key
        #ifdef _DEBUG
        for (j=0; j<ntohs(l4_pubkey->pubkeylen); j++) {
            printf("%c", publickey[j]);
        }
        #endif
        
        // Construct a 'Propose Link Key' packet
        l2->original_source_addr = htons(src);
        l4->type = TYPE_LINKKEYEXCHANGE_PROPOSE;
        l4_propose->linkkeylen = htons(LINKKEY_LENGTH);
        
        
        // Get a random number that is large enough to be used as AES Key and IV for the link key
        RAND_bytes(linkkey, LINKKEY_LENGTH);
        
        #ifdef _DEBUG
        printf("Randomly Generated Key|IV = ");
        for(j=0; j<LINKKEY_LENGTH; j++) {
            printf("%.2x", linkkey[j]);
        }
        printf("\n");
        #endif
        
        
        // Encrypt the link key with RSA public key
        encrypted_linkkey_length = public_encrypt(linkkey, LINKKEY_LENGTH, publickey, encrypted_linkkey);
        
        #ifdef _DEBUG
        printf("Encrypted Key|IV = ");
        for(j=0; j<encrypted_linkkey_length; j++) {
            printf("%.2x", encrypted_linkkey[j]);
        }
        printf("\n");
        #endif
        
        // Put the encrypted link key and its length into the packet
        l4_propose->enclinkkeylen = htons((uint16_t) encrypted_linkkey_length);
        memcpy(buffer_send + header_length + sizeof(struct layer4_linkkeyexchange_propose), encrypted_linkkey, encrypted_linkkey_length);
        
        // Send the 'Propose Link Key' packet
        send(sockfd[i], buffer_send, header_length + sizeof(struct layer4_linkkeyexchange_propose) + encrypted_linkkey_length, 0);
        printf("Send Purposed Link Key exchangeid=0x%.2x\n", l4->exchgid);
        

        // Receive an 'Agree' packet within the timeout
        recvlen = recv(sockfd[i], buffer_send, MTU, 0);
        if ((recvlen != -1) && (l4->type == TYPE_LINKKEYEXCHANGE_AGREE)) {
            
            printf("Recv Agree from host=%d exchangeid=0x%.2x\n", ntohs(l2->original_source_addr), l4->exchgid);
            
            // Construct the link key file name
            strcpy(linkkeyfile, keystoredir);
            strcat(linkkeyfile, "/linkkey.");
            strcat(linkkeyfile, interface[i].interface_name);
            
            // Open the file
            if (!(file_linkkey = fopen(linkkeyfile, "wb"))) {
                printf("** Failed to write the link key to file %s\n", linkkeyfile);
                continue;
            }
            
            // Write the link key to a binary file
            fwrite(linkkey, LINKKEY_LENGTH, 1, file_linkkey);
            fclose(file_linkkey);
            
            // Ensure the file is readable/writeable by only user
            chmod(linkkeyfile, 0600);
            
            printf("** The link key is saved to file %s\n", linkkeyfile);
            
        }
        else {
            printf("** Failed to receive agree!");
        }
        
        // Close the socket
        close(sockfd[i]);
        
    }
}
