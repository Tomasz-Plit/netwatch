#include "../include/helpers.h"

uint16_t rd16(const unsigned char *p){ return (p[0] << 8) | p[1]; }
uint32_t rd32(const unsigned char *p){
    return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3]);
}
