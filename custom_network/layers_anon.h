//
//  layers.h
//  custom_network
//
//  Created by Peera Yoodee on 10/6/15.
//

#ifndef custom_network_layers_h
#define custom_network_layers_h

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

typedef unsigned char uchar_t;

// Addressing
#define SOURCE_ADDR_LEN 2
struct layer2 {
    uint16_t original_source_addr;
    
};

// Routing
#define MAX_HOPS	4
#define TYPE_ICMP 0
#define TYPE_UDP 1
#define TYPE_LINKKEYEXCHG 2
struct layer3 {
    uint8_t  type;
    uint8_t  ttl;
    uint8_t  source_routing[MAX_HOPS];
};

// Transport
#define TYPE_ICMP_PING_REQUEST 0
#define TYPE_ICMP_PING_REPLY 1
struct layer4_icmp {
    uint16_t type;          // 0=Ping_Request 1=Ping_Reply
    uint16_t seq;
};

struct layer4_udp {
    uint8_t  dport;
    uint8_t  sport;
    uint16_t len;
    uint8_t  padding[4];
};

struct layer4_linkkeyexchange {
    uint8_t type;
    uint8_t exchgid;
};

struct layer4_linkkeyexchange_pubkey {
    uint8_t type;
    uint8_t exchgid;
    uint16_t pubkeylen;
};

struct layer4_linkkeyexchange_propose {
    uint8_t type;
    uint8_t exchgid;
    uint16_t linkkeylen;
    uint16_t enclinkkeylen;
};




// Application
struct iperf {
    uint32_t padding;
    uint32_t id;
};


#endif
