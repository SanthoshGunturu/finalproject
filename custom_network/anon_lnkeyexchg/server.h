//
//  server.h
//  custom_network
//
//

#ifndef __custom_network__server__
#define __custom_network__server__

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

#include <sys/stat.h>
#include <sys/select.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "../interface.h"
#include "../layers_anon.h"
#include "define.h"
#include "rsa.h"

#define _DEBUG

void server(uint16_t src, const char *keystoredir, int num_interfaces, struct interface **interface);

#endif /* defined(__custom_network__server__) */
