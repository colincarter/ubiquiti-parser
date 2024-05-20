#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>

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

uint16_t read_uint16_be(uint16_t value)
{
    return (((value & 0x00FF) << 8) |
            ((value & 0xFF00) >> 8));
}

struct header {
    uint8_t version;
    uint8_t cmd;
    uint16_t length;
};

struct ubiquity {
    struct header head;
    char *protocol;
};

static bool parse_v1_packet(struct ubiquity *ubi, uint8_t *data) {
    ubi->protocol = 'v1';
}

static bool parse_v2_packet(uint8_t cmd, struct ubiquity *ubi, uint8_t *data) {
    ubi->protocol = "v2";
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
        return parse_v2_packet(cmd, ubi, d);
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

    printf("cmd = %d\n", parsed_data.head.cmd);
    printf("type = %d\n", parsed_data.head.version);
    printf("length = %d\n", parsed_data.head.length);
}
