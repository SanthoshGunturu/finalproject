//
//  server.c
//  custom_network
//
//  Created by Peera Yoodee on 11/5/15.
//

#include "server.h"

void server(uint16_t src, const char *keystoredir, int num_interfaces, struct interface **interfaces) {
    
    int i, j;
    
    struct interface *interface = *interfaces;
    
    char *privatekeyfile, *publickeyfile, linkkeyfile[strlen(keystoredir) + 20];
    char genrsa_command[1000];
    FILE *file_privatekey, *file_publickey, *file_linkkey;
    
    uint16_t file_public_size, file_private_size;
    
    char agree[6] = "Agree";
    unsigned char *buffer_publickey, *buffer_privatekey, buffer_recv[MTU], *encrypted_linkkey, linkkey[LINKKEY_LENGTH];
    
    struct layer2 *l2;
    //struct layer3 *l3;
    struct layer4_linkkeyexchange *l4;
    struct layer4_linkkeyexchange_pubkey *l4_pubkey;
    struct layer4_linkkeyexchange_propose *l4_propose;
    size_t header_length;
    
    // Socket and its filter
    ssize_t recvlen;
    int sockfd[num_interfaces];
    struct sockaddr_ll sa[num_interfaces];
    struct packet_mreq mreq[num_interfaces];
    struct sock_fprog prog_filter;
    struct sock_filter incoming_filter[] = {    // ether[2]=2 and (ether[8]=0 or ether[8]=2) and !(ether[0]=0xff and ether[1]=0xee)
        { 0x30, 0, 0, 0x00000002 }, // Position of Layer3:Type
        { 0x15, 0, 8, 0x00000002 }, //   2 means Link Key Exchange Packet
        { 0x30, 0, 0, 0x00000008 }, // Position of Layer4:LinkKeyExchange:Type
        { 0x15, 1, 0, 0x00000000 }, //   0 means Link Key Exchange Request Packet  OR
        { 0x15, 0, 5, 0x00000002 }, //   2 means Proposed Link Key
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
    
    // Select()
    int selectval, sockfd_max = -1;
    fd_set readfds;
    FD_ZERO(&readfds);
    
    l2 = (struct layer2 *) buffer_recv;
    //l3 = (struct layer3 *) (buffer_recv + sizeof(struct layer2));
    l4 = (struct layer4_linkkeyexchange *) (buffer_recv + sizeof(struct layer2) + sizeof(struct layer3));
    l4_pubkey  = (struct layer4_linkkeyexchange_pubkey *) (buffer_recv + sizeof(struct layer2) + sizeof(struct layer3));
    l4_propose = (struct layer4_linkkeyexchange_propose *) (buffer_recv + sizeof(struct layer2) + sizeof(struct layer3));
    header_length = sizeof(struct layer2) + sizeof(struct layer3);

    
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
            "/usr/bin/openssl genrsa -out %s %d && /usr/bin/openssl rsa -in %s -outform PEM -pubout -out %s && chmod 400 %s %s",
            privatekeyfile, RSA_KEY_LENGTH_BIT, privatekeyfile, publickeyfile, privatekeyfile, publickeyfile
        );
        
        // Execute the shell command
        if (system(genrsa_command) != 0) {
            fprintf(stderr, "Error: could not generate an RSA public/private key pair");
            return;
        }
    }
    
    // Get the size of the private key file
    fseeko(file_privatekey, 0 , SEEK_END);
    file_private_size = (uint16_t) ftello(file_privatekey);
    fseeko(file_privatekey, 0 , SEEK_SET);
    
    buffer_privatekey = (unsigned char *) malloc(file_private_size);
    
    // Read the public key file into buffer
    if (!fread(buffer_privatekey, file_private_size, 1, file_privatekey) == file_private_size) {
        fprintf(stderr, "Error: error reading private key file");
        return;
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
    

    
//    int i;
//    for (i=0; i<file_public_size; i++) {
//        printf("%c", buffer_publickey[i]);
//    }
//    
//    printf("%u", file_public_size);
    
    // Initialize socket buffer
    memset(buffer_recv, 0, sizeof(buffer_recv));

    
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
        if (setsockopt(sockfd[i], SOL_SOCKET, SO_ATTACH_FILTER, &prog_filter, sizeof(prog_filter)) < 0)
        {
            fprintf(stderr, "Error: cannot set SO_ATTACH_FILTER in server()\n");
            exit(2);
        }
        
        // Bind socket to interface
        if(bind(sockfd[i] ,(struct sockaddr *) &sa[i], sizeof(sa[i])) <0) {
            fprintf(stderr, "Error bind raw socket failed in server()\n");
            exit(3);
        }
        
        // Add the sockfd to the fd set
        FD_SET(sockfd[i], &readfds);
        if (sockfd[i] > sockfd_max) {
            sockfd_max = sockfd[i];
        }

    }

    while (1) {
        
        // Blocking call, wait for sockets to get ready
        selectval = select(sockfd_max+1, &readfds, NULL, NULL, NULL);

        if (selectval == -1) {
            perror("select");
        }
        else {
            for (i=0; i<num_interfaces; i++) {
                if (FD_ISSET(sockfd[i], &readfds)) {
                    
                    recvlen = recv(sockfd[i], buffer_recv, MTU, 0);
                    
                    if (recvlen < header_length + sizeof(struct layer4_linkkeyexchange)) {
                        break;
                    }
                    
                    if (l4->type == TYPE_LINKKEYEXCHANGE_REQUEST) { // Receive a 'Link Key Exchange Request' packet
                        
                        printf("Recv Request from host=%d exchangeid=0x%.2x\n", ntohs(l2->original_source_addr), l4->exchgid);
                        
                        // Reply with a 'Public Key Response' packet
                        l2->original_source_addr = htons(src);
                        l4->type = TYPE_LINKKEYEXCHANGE_PUBKEY;
                        l4_pubkey->pubkeylen = htons(file_public_size);
                        memcpy(buffer_recv + header_length + sizeof(struct layer4_linkkeyexchange_pubkey), buffer_publickey, file_public_size);
                        
                        send(sockfd[i], buffer_recv, header_length + sizeof(struct layer4_linkkeyexchange_pubkey) + file_public_size, 0);
                        printf("Send PublicKey exchangeid=0x%.2x\n", l4->exchgid);
                        
                    }
                    else if (l4->type == TYPE_LINKKEYEXCHANGE_PROPOSE) { // Receive a 'Proposed Link Key' packet
                        
                        printf("Recv Proposed Link Key from host=%d exchangeid=0x%.2x\n", ntohs(l2->original_source_addr), l4->exchgid);
                        
                        // Get the encrypted link key
                        encrypted_linkkey = buffer_recv + header_length + sizeof(struct layer4_linkkeyexchange_propose);

                        #ifdef _DEBUG
                        printf("Encrypted Key|IV = ");
                        for (j=0; j<ntohs(l4_propose->enclinkkeylen); j++) {
                            printf("%.2x", encrypted_linkkey[j]);
                        }
                        printf("\n");
                        #endif
                        
                        // Decrypt to obtain the link key
                        private_decrypt(encrypted_linkkey, ntohs(l4_propose->enclinkkeylen), buffer_privatekey, linkkey);
                        
                        #ifdef _DEBUG
                        printf("Key|IV = ");
                        for (j=0; j<LINKKEY_LENGTH; j++) {
                            printf("%.2x", linkkey[j]);
                        }
                        printf("\n");
                        #endif
                        
                        
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
                        
                        
                        // Reply with an Agree packet
                        l2->original_source_addr = htons(src);
                        l4->type = TYPE_LINKKEYEXCHANGE_AGREE;
                        memcpy(buffer_recv + header_length + sizeof(struct layer4_linkkeyexchange), agree, strlen(agree));
                        
                        send(sockfd[i], buffer_recv, header_length + sizeof(struct layer4_linkkeyexchange) + strlen(agree), 0);
                        printf("Send Agree exchangeid=0x%.2x\n", l4->exchgid);
                        
                    }
                    
                    break;
                }

            }
        }
        
        for (i=0; i<num_interfaces; i++) {
            FD_SET(sockfd[i], &readfds);
        }
        
    }
}
