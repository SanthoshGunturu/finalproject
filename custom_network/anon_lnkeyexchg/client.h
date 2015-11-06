//
//  client.h
//  custom_network
//
//  Copyright (c) 2015 Peera Yoodee. All rights reserved.
//

#ifndef __custom_network__client__
#define __custom_network__client__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <fcntl.h>

#include <linux/if_packet.h>
#include <linux/filter.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "../interface.h"
#include "../layers_anon.h"

void client(uint16_t src, const char *keystoredir, int num_interfaces, struct interface *interface);

#endif /* defined(__custom_network__client__) */
