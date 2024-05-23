#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include "parser.h"

const uint8_t data[] = {
  2, 6, 0, 155, 2, 0, 10, 252, 236, 218, 25, 99, 240, 192, 168, 1, 20, 1, 0, 6,
  252, 236, 218, 25, 99, 240, 10, 0, 4, 0, 13, 248, 59, 11, 0, 4, 85, 66, 78,
  84, 12, 0, 4, 85, 55, 76, 84, 3, 0, 36, 66, 90, 46, 113, 99, 97, 57, 53, 54,
  120, 46, 118, 52, 46, 51, 46, 50, 52, 46, 49, 49, 51, 53, 53, 46, 50, 48, 49,
  50, 48, 55, 46, 49, 55, 49, 55, 22, 0, 12, 52, 46, 51, 46, 50, 52, 46, 49, 49,
  51, 53, 53, 21, 0, 4, 85, 55, 76, 84, 23, 0, 1, 1, 24, 0, 1, 0, 25, 0, 1, 1,
  26, 0, 1, 1, 19, 0, 6, 252, 236, 218, 25, 99, 240, 18, 0, 4, 0, 2, 202, 219,
  27, 0, 5, 51, 46, 52, 46, 49, 36, 0, 8, 90, 86, 255, 125, 241, 210, 243, 21
};

uint16_t read_uint16_be(uint16_t value) {
    return (((value & 0x00FF) << 8) |
            ((value & 0xFF00) >> 8));
}

struct header {
    uint8_t version;
    uint8_t cmd;
    uint16_t length;
};

enum protocol {
    v1 = 1,
    v2 = 2
};

struct mac_address {
    unsigned char *mac_address;
    struct mac_address *next;
};

struct ubiquity {
    struct header head;
    enum protocol protocol;
    struct mac_addresses *mac_address;
};

static bool parse_v1_packet(struct ubiquity *ubi, uint8_t *data) {
    ubi->protocol = v1;

    return true;
}

struct tld {
    uint8_t type;
    uint16_t length;
    uint8_t *data;
};

void *read_data(u_int16_t len, void *data) {
    void *d = malloc(len+1);
    if (d == NULL) 
        return NULL;

    memcpy(d, data, len);

    return d;
}

const char *hex_val = "0123456789ABCDEF";

// Given a byte return the hex equivalent
// 2 bytes result: 255 => FF
void byte_to_hex(uint8_t byte, char *hex) {
    char *out = hex;
    out[0] = hex_val[(byte >> 4) & 0xf];
    out[1] = hex_val[byte & 0xf];
}

void read_mac_address(uint8_t *data, char *mac_address) {
    char *mac = mac_address;
    for (int i = 0; i < 6; i++) {
        byte_to_hex(data[i], mac);

        mac += 2; // skip data just written

        if (i != 5) {
            *mac++ = ':';
        }
    }

    *mac = '\0';  // 0 terminate string
}

char byte_to_char(uint8_t b) {
    return (char)b ;
}

void read_ip_address(uint8_t *data, char *ip_address) {
    // sprintf(ip_address, "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);
    *ip_address++ = byte_to_char(data[0]);
    *ip_address++ = '.';
    *ip_address++ = byte_to_char(data[1]);
    *ip_address++ = '.';
    *ip_address++ = byte_to_char(data[2]);
    *ip_address++ = '.';
    *ip_address++ = byte_to_char(data[3]);
}

static bool parse_v2_packet(uint8_t cmd, struct ubiquity *ubi, uint8_t *data, size_t len) {
    uint8_t *d = data;
    uint8_t *end = d + len;

    ubi->protocol = v2;

    d += sizeof(struct header);

    while (d < end) {
        struct tld tld;

        tld.type = *d++;
        tld.length = read_uint16_be(*(uint16_t *)d);
        d += sizeof(tld.length);
        
        printf("type=%d length=%d\n", tld.type, tld.length);

        tld.data = read_data(tld.length, d);

        switch (tld.type) {
            case V2_IPINFO: {
                    // tld.data is 6 bytes
                    char mac_address[17+1] = {0};
                    char ip_address[12+4+1] = {0};
                    read_mac_address(tld.data, mac_address);
                    read_ip_address(tld.data + 6, ip_address);
                    printf("mac_address=%s\n", mac_address);
                    printf("ip address=%s\n", ip_address);
                }
                break;
        }

        d += tld.length;

        free(tld.data);
    }

    return true;
}


bool parse(struct ubiquity *ubi, uint8_t *d, size_t len) {
    uint8_t *data = d;

    uint8_t version = *data++;
    uint8_t cmd = *data++;
    uint16_t length = read_uint16_be(*((uint16_t *)data));

    if (length + 4 > len) {
        return false;
    }

    if (version == 1 && cmd == 0 && length == 0) {
        return false;
    }

    memset(ubi, 0, sizeof(struct ubiquity));

    ubi->head.version = version;
    ubi->head.cmd = cmd;
    ubi->head.length = length;

    if (version == 1 && cmd == 0) {
        return parse_v1_packet(ubi, d);
    } else if (version == 2) {
        return parse_v2_packet(cmd, ubi, d, len);
    }

    return false;
}

int main() {
    struct ubiquity parsed_data;
    
    bool parse_ok = parse(&parsed_data, (uint8_t *)data, sizeof(data));

    if (!parse_ok) {
        printf("Failed to parse\n");
        return 1;
    }
}
