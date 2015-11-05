//
//  main.c
//  custom_network
//
//  Copyright (c) 2015 Peera Yoodee. All rights reserved.
//

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/stat.h>

#include "../interface.h"

#include "server.h"
#include "client.h"

void print_usage();

int main(int argc, const char * argv[]) {
    
    char *keystoredir;
    char *arg_interface = NULL;
    char *token, *dup;
    
    int i;
    int num_input_interfaces = 0;
    
    uint16_t src;
    
    struct stat s;
    struct interface *input_interface;
    
    if (argc <= 5) {
        print_usage();
        exit(1);
    }
    
    if (!((strcmp("-s", argv[1]) == 0) || (strcmp("-c", argv[1]) == 0))) {
        print_usage();
        exit(1);
    }
    
    if (strcmp("-src", argv[2]) != 0) {
        print_usage();
        exit(1);
    }
    
    if (strcmp("-f", argv[4]) != 0) {
        print_usage();
        exit(1);
    }
    
    if (strcmp("-i", argv[6]) != 0) {
        print_usage();
        exit(1);
    }
    
    src = (uint16_t) atoi(argv[3]);
    keystoredir = strdup(argv[5]);
    
    
    // Remove / if the dirname ends with a slash
    if (keystoredir[strlen(keystoredir)-1] == '/') {
        keystoredir[strlen(keystoredir)-1] = '\0';
    }
    
    // Check if the keystore directory exists
    if (stat(keystoredir, &s) == -1) {
        fprintf(stderr, "Error: keystore %s does not exist\n", keystoredir);
        exit(1);
    }
    else {
        if(!S_ISDIR(s.st_mode)) {
            fprintf(stderr, "Error: keystore %s is not a directory\n", keystoredir);
            exit(1);
        }
    }
    
    arg_interface = strdup(argv[7]);
    
    /*
     * Network Interfaces
     *
     */
    // Count commas to get the upper bound of the number of interfaces
    for (i=0; i<strlen(arg_interface); i++) {
        if (arg_interface[i] == ',') num_input_interfaces++;
    }
    num_input_interfaces++;
    
    // Allocate input interface array
    input_interface = (struct interface *) malloc(num_input_interfaces * sizeof(struct interface));
    
    // Parse input interfaces
    num_input_interfaces = 0;
    dup = strdup(arg_interface);
    while ((token = strtok(dup, ",")) != NULL) {
        
        strcpy(input_interface[num_input_interfaces].interface_name, token);
        fill_interface_info(&input_interface[num_input_interfaces]);
        
        // Interface name is valid
        if (input_interface[num_input_interfaces].interface_index != -1) {
            num_input_interfaces++;
        }
        
        dup = NULL;
        
    }
    free(arg_interface);
    free(token);
    
    // Check if the number of interfaces is at least 1
    if (num_input_interfaces <= 0) {
        fprintf(stderr, "Error: no valid network interfaces\n");
        exit(1);
    }
    
    // Print listening interfaces information
    #ifdef _VERBOSE
    fprintf(stderr, "[NETWORK INTERFACES]\n");
    fprintf(stderr, "   Number of network interfaces: %d\n", num_input_interfaces);
    fprintf(stderr, "   %-5s %-6s %-19s %-15s\n", "Dev", "DevId", "Interface MAC addr", "Inf IP addr");
    for(i=0; i<num_input_interfaces; i++) {
        fprintf(stderr, "%2d ", i+1);
        fprintf_interface(stderr, &input_interface[i]);
    }
    fprintf(stderr, "\n");
    #endif
    
    
    
    if (strcmp("-s", argv[1]) == 0) {
        server(src, keystoredir, num_input_interfaces, input_interface);
    }
    else if (strcmp("-c", argv[1]) == 0) {
        client(src, keystoredir, num_input_interfaces, input_interface);
    }
    
    return 0;
    
}

void print_usage() {
    fprintf(stderr, "Error: invalid options\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  lnkeyexchg -s -src 1 -f /path/to/keystore/directory -i eth0,eth1\n");
    fprintf(stderr, "  lnkeyexchg -c -src 2 -f /path/to/keystore/directory -i eth0\n");
}

