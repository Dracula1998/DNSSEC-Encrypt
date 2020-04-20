//
// Created by ghost on 19-5-6.
//

#ifndef FIREWALL_CONSTANTS_H
#define FIREWALL_CONSTANTS_H

#define FILTER_BOOL int
#define FILTER_TRUE 1
#define FILTER_FALSE 0

#define NAME "[Netfilter Firewall] "

// ==== logger level ======

#define LOGGER_DEBUG (-1)
#define LOGGER_INFO 0
#define LOGGER_OK 1
#define LOGGER_LOW 2
#define LOGGER_WARN 3
#define LOGGER_FATAL 4

#define DNS_PACKET_NO 0
#define DNS_PACKET_YES 1
#define DNS_PACKET_QUERY 2
#define DNS_PACKET_RESPONSE 3

// ==== console color ====

// Reset
#define COLOR_RESET "\033[0m"  // Text Reset

// Regular Colors
#define COLOR_BLACK "\033[0;30m"   // BLACK
#define COLOR_RED "\033[0;31m"     // RED
#define COLOR_GREEN "\033[0;32m"   // GREENK
#define COLOR_YELLOW "\033[0;33m"  // YELLOW
#define COLOR_BLUE "\033[0;34m"    // BLUE
#define COLOR_PURPLE "\033[0;35m"  // PURPLE
#define COLOR_CYAN "\033[0;36m"    // CYAN
#define COLOR_WHITE "\033[0;37m"   // WHITE

// Bold
#define COLOR_BLACK_BOLD "\033[1;30m"  // BLACK
#define COLOR_RED_BOLD "\033[1;31m"    // RED
#define COLOR_GREEN_BOLD "\033[1;32m"  // GREEN
#define COLOR_YELLOW_BOLD "\033[1;33m" // YELLOW
#define COLOR_BLUE_BOLD "\033[1;34m"   // BLUE
#define COLOR_PURPLE_BOLD "\033[1;35m" // PURPLE
#define COLOR_CYAN_BOLD "\033[1;36m"   // CYAN
#define COLOR_WHITE_BOLD "\033[1;37m"  // WHITE

// Underline
#define COLOR_BLACK_UNDERLINED "\033[4;30m"  // BLACK
#define COLOR_RED_UNDERLINED "\033[4;31m"    // RED
#define COLOR_GREEN_UNDERLINED "\033[4;32m"  // GREEN
#define COLOR_YELLOW_UNDERLINED "\033[4;33m" // YELLOW
#define COLOR_BLUE_UNDERLINED "\033[4;34m"   // BLUE
#define COLOR_PURPLE_UNDERLINED "\033[4;35m" // PURPLE
#define COLOR_CYAN_UNDERLINED "\033[4;36m"   // CYAN
#define COLOR_WHITE_UNDERLINED "\033[4;37m"  // WHITE

// Background
#define COLOR_BLACK_BACKGROUND "\033[40m"  // BLACK
#define COLOR_RED_BACKGROUND "\033[41m"    // RED
#define COLOR_GREEN_BACKGROUND "\033[42m"  // GREEN
#define COLOR_YELLOW_BACKGROUND "\033[43m" // YELLOW
#define COLOR_BLUE_BACKGROUND "\033[44m"   // BLUE
#define COLOR_PURPLE_BACKGROUND "\033[45m" // PURPLE
#define COLOR_CYAN_BACKGROUND "\033[46m"   // CYAN
#define COLOR_WHITE_BACKGROUND "\033[47m"  // WHITE

// High Intensity
#define COLOR_BLACK_BRIGHT "\033[0;90m"  // BLACK
#define COLOR_RED_BRIGHT "\033[0;91m"    // RED
#define COLOR_GREEN_BRIGHT "\033[0;92m"  // GREEN
#define COLOR_YELLOW_BRIGHT "\033[0;93m" // YELLOW
#define COLOR_BLUE_BRIGHT "\033[0;94m"   // BLUE
#define COLOR_PURPLE_BRIGHT "\033[0;95m" // PURPLE
#define COLOR_CYAN_BRIGHT "\033[0;96m"   // CYAN
#define COLOR_WHITE_BRIGHT "\033[0;97m"  // WHITE

// Bold High Intensity
#define COLOR_BLACK_BOLD_BRIGHT "\033[1;90m" // BLACK
#define COLOR_RED_BOLD_BRIGHT "\033[1;91m"   // RED
#define COLOR_GREEN_BOLD_BRIGHT "\033[1;92m" // GREEN
#define COLOR_YELLOW_BOLD_BRIGHT "\033[1;93m" // YELLOW
#define COLOR_BLUE_BOLD_BRIGHT "\033[1;94m"  // BLUE
#define COLOR_PURPLE_BOLD_BRIGHT "\033[1;95m" // PURPLE
#define COLOR_CYAN_BOLD_BRIGHT "\033[1;96m"  // CYAN
#define COLOR_WHITE_BOLD_BRIGHT "\033[1;97m" // WHITE

// High Intensity backgrounds
#define COLOR_BLACK_BACKGROUND_BRIGHT "\033[0;100m" // BLACK
#define COLOR_RED_BACKGROUND_BRIGHT "\033[0;101m" // RED
#define COLOR_GREEN_BACKGROUND_BRIGHT "\033[0;102m" // GREEN
#define COLOR_YELLOW_BACKGROUND_BRIGHT "\033[0;103m" // YELLOW
#define COLOR_BLUE_BACKGROUND_BRIGHT "\033[0;104m" // BLUE
#define COLOR_PURPLE_BACKGROUND_BRIGHT "\033[0;105m" // PURPLE
#define COLOR_CYAN_BACKGROUND_BRIGHT "\033[0;106m"  // CYAN
#define COLOR_WHITE_BACKGROUND_BRIGHT "\033[0;107m"   // WHITE



#define DATA_ENCRYPT 1
#define DATA_DECRYPT 0
#define BLK_SIZE 16
#define RSA_KEY_LEN 128
#define AES_KEY_LEN 32
#define AES_IV_LEN 16
unsigned char *priv_key =
    "\x30\x82\x02\x5C\x02\x01\x00\x02\x81\x81\x00\xCA\xA3\x2B\x5A\xDB"
    "\xAC\xBB\xE1\xFF\x5E\x13\x42\x30\x21\x84\xE2\xF6\x5D\x99\xE5\x8A"
    "\x48\x05\xCB\x93\xDA\x1E\x29\x60\xC0\xDF\x33\xF0\xC2\x8C\xD4\x70"
    "\x83\xD4\x10\x17\x39\x22\x1C\x81\xDF\x47\x83\x7D\xB8\xEA\xAA\xEC"
    "\xCD\x93\xBE\x90\xB0\x50\xAC\xD5\x6A\x8C\x34\xC6\xFC\xA5\xFA\x03"
    "\x2C\x12\x7A\xA5\x2B\x09\xE9\xBF\x84\x98\xFA\x8B\xFC\xF9\xEA\xAE"
    "\x15\x52\x3D\xBE\x47\x38\x3E\x07\x26\xB0\x8A\x09\x1E\xA0\x95\x80"
    "\x80\xC4\x6F\xD9\x68\xE8\x59\xC4\xBE\xCC\xE6\x97\xF5\x9E\x4A\x06"
    "\x23\x3B\x23\x11\xC4\x12\xFB\x6A\x33\xB6\xCF\x02\x03\x01\x00\x01"
    "\x02\x81\x80\x61\xDD\x09\xDC\x38\x89\xA4\xB7\x91\xE0\x3A\x46\xD5"
    "\xFD\xEA\x32\xBE\xAF\x17\xDB\x2E\xBC\x77\xE8\x08\xC0\xE7\x9E\x2E"
    "\x37\x17\xD4\xFA\xEA\xCA\x9E\xF2\xB4\x08\x1F\xB9\x47\x83\x7C\xE7"
    "\x10\x11\x76\xA4\xAA\x40\xD3\x49\xC8\x43\x19\x5E\xC1\x78\x44\xF0"
    "\x51\x23\xE2\xA0\x2B\x1D\xD0\x60\x97\x96\x2F\x0A\x73\xEA\xAD\xB8"
    "\x9A\xB6\x18\x27\x6E\xC6\x52\x10\xCC\x64\xC7\x8C\xC0\x2C\xD2\xCD"
    "\xAF\x56\x2E\x35\x14\xA9\x05\xEF\xB0\x47\x51\xE5\x0F\x6A\xDC\x4E"
    "\xA0\x2F\xC8\xC3\x12\x26\xA6\x6C\xDC\x7C\xB6\xF4\xBC\x34\x93\x60"
    "\x0C\x7F\xE9\x02\x41\x00\xFC\x62\xD1\x5A\xD5\x62\xEB\xC9\x89\x45"
    "\x64\xCA\x3B\x42\x55\xCE\xCC\x89\x9F\x5C\x0E\x1E\x76\x78\x0F\x83"
    "\x37\x8A\xA2\x8F\x03\x77\xE3\xAA\x6F\x0C\x03\xC3\xB6\xB1\xC0\x6F"
    "\xCD\xB6\x71\xC8\x87\xAB\x8D\x37\x4A\x6A\x6C\x1D\xCF\xC1\x59\x08"
    "\x8F\xC6\xF1\x25\x18\x8B\x02\x41\x00\xCD\x89\xFC\x63\x35\xA5\xD4"
    "\xEC\x4B\x19\xA6\xB1\xF5\xA2\xCA\x1F\xB1\x31\x10\x93\x56\xDE\x0E"
    "\x2B\x99\x13\x45\x49\xF9\xA4\x13\x8D\x5E\x3B\xF4\x90\x33\xEB\x28"
    "\x0B\x45\xAE\xA2\xF3\x6A\xEE\x74\x33\x05\x06\x9B\x2C\xA9\x78\x69"
    "\xBA\x67\xBC\x5E\x0B\x04\x07\x9F\x4D\x02\x41\x00\xC6\x97\x3B\x04"
    "\xAE\x43\x58\x25\x0C\xCE\x7D\xB0\x63\x50\x9F\x14\x49\xFD\x40\x57"
    "\xBF\x04\x59\x53\xBF\x61\x10\xA3\x15\xA6\x52\xA4\x53\x90\x18\x30"
    "\xEC\x05\x64\x0C\x19\xCF\xDF\x9E\x5F\x89\xDA\xB7\x32\x36\xFF\x67"
    "\x1E\x0B\x97\x1E\x1C\x60\x90\x41\x8A\x1E\x16\x61\x02\x40\x71\x24"
    "\x80\x16\x6C\xB5\xB8\x9B\xCA\x4B\x78\x83\x85\xDF\xF2\xBB\xB7\x62"
    "\x76\xE9\x64\x6C\x20\x08\xC7\xDE\xDF\xC9\x74\xEE\x69\x04\xEC\xD6"
    "\xBC\x2D\x95\x26\xE1\x88\x32\xF7\x8B\x23\xCB\xBD\x2F\xA1\xD6\x26"
    "\x68\xCD\x11\x0D\x03\xC6\x64\xCC\x40\x48\x78\x13\x6A\x11\x02\x40"
    "\x7F\xF6\xF5\xAF\xEB\xCA\x8A\x52\xE0\x2B\xA9\xA4\x56\x6B\xC3\x1F"
    "\x71\x0E\xBE\x5E\xF5\xB0\x10\x3F\x40\x18\x20\xB9\xFC\xC2\xF2\x22"
    "\x4B\x55\x4A\x05\x4C\x44\xD6\x43\x44\xD4\x9D\x61\xB1\x12\x98\x4E"
    "\xE6\x1D\xA5\xFE\x73\xEC\x6E\x7B\x53\xF3\x1A\x5C\x56\x7E\x44\x41";

int priv_key_len = 608;

unsigned char *pub_key =
    "\x30\x81\x89\x02\x81\x81\x00\xCA\xA3\x2B\x5A\xDB\xAC\xBB\xE1\xFF"
    "\x5E\x13\x42\x30\x21\x84\xE2\xF6\x5D\x99\xE5\x8A\x48\x05\xCB\x93"
    "\xDA\x1E\x29\x60\xC0\xDF\x33\xF0\xC2\x8C\xD4\x70\x83\xD4\x10\x17"
    "\x39\x22\x1C\x81\xDF\x47\x83\x7D\xB8\xEA\xAA\xEC\xCD\x93\xBE\x90"
    "\xB0\x50\xAC\xD5\x6A\x8C\x34\xC6\xFC\xA5\xFA\x03\x2C\x12\x7A\xA5"
    "\x2B\x09\xE9\xBF\x84\x98\xFA\x8B\xFC\xF9\xEA\xAE\x15\x52\x3D\xBE"
    "\x47\x38\x3E\x07\x26\xB0\x8A\x09\x1E\xA0\x95\x80\x80\xC4\x6F\xD9"
    "\x68\xE8\x59\xC4\xBE\xCC\xE6\x97\xF5\x9E\x4A\x06\x23\x3B\x23\x11"
    "\xC4\x12\xFB\x6A\x33\xB6\xCF\x02\x03\x01\x00\x01";

int pub_key_len = 140;

// unsigned char *priv_key =
//     "\x30\x82\x01\x3F\x02\x01\x00\x02\x42\x01\x4D\x79\x64\xFB\x07\xF4"
//     "\x85\x11\x09\x1E\xA5\x9C\x96\x14\x7D\x75\x52\x8E\x44\x30\x23\xD4"
//     "\x39\x68\xE2\x4C\xDD\x4C\xF2\xD6\x4F\xED\x38\x73\x1D\x23\x57\x2C"
//     "\xF9\xC9\xA3\x45\x8E\xB3\xDC\x7B\xD7\x05\xA4\x9D\x25\x63\xD5\x62"
//     "\x59\xA2\x2A\x72\xBD\xE3\xC6\x7B\x31\xDF\x47\x02\x03\x01\x00\x01"
//     "\x02\x42\x00\x83\xE8\xF5\x2C\xE7\xA4\xAD\xCE\x63\x51\x20\x29\xA4"
//     "\xA4\x4E\x4C\x4E\x6F\xC0\x41\x5A\xAA\xE4\x5A\xBC\xC9\xB2\xF0\x71"
//     "\x4E\x9D\x27\x26\x06\x7F\x48\x30\x2B\x4C\x17\x26\x39\xB7\x1E\x13"
//     "\x97\xCA\x45\xC7\x4D\xD2\xDD\x02\xC8\x23\x9C\x40\xF1\x23\xEA\xE7"
//     "\x85\x64\xE4\x81\x02\x21\x18\xA9\xCE\xF6\x56\x6F\x04\xBD\x1D\xB8"
//     "\xB5\x2C\x5A\x55\x63\x6D\xCA\x3D\x61\xF0\xD0\xA9\xA0\x0A\xF5\x0C"
//     "\xCC\x9C\xDF\xA2\x8A\x35\xB1\x02\x21\x0D\x85\x64\x4F\x0E\xB0\xCD"
//     "\x17\x15\xB7\x89\x3A\x4C\x69\x62\xC0\x2A\xC2\xBA\xB1\x18\xA8\x63"
//     "\x47\x73\xD5\x85\x8F\x4F\x98\xFA\x0A\x77\x02\x21\x17\x42\x5D\x8A"
//     "\x77\xAD\x2F\x7C\xE2\xC0\xC5\x2B\xD4\xED\x5E\x5D\xB6\x32\xF9\x60"
//     "\xD0\x88\x88\x04\x8D\x61\xCA\xBD\xCF\x32\x4C\xC1\xA1\x02\x21\x07"
//     "\x9B\xB0\x96\xDF\xB0\x52\xA7\x13\xBC\x43\xC6\x7F\x2A\xA9\xBB\x72"
//     "\x14\x42\xD2\xD6\x0A\x22\x5B\x19\x6D\xE3\x8A\x81\x82\x95\xE7\xFF"
//     "\x02\x21\x08\x9F\x2E\xCE\xE8\xF3\x3D\x4F\x96\x17\xBF\xE2\xBD\x8B"
//     "\xA8\xF9\xEF\xC1\x47\x30\xA3\x57\xA5\xB4\xA7\xD2\x0E\x39\x4D\x39"
//     "\xB7\x87\xAB";

// int priv_key_len = 323;

// unsigned char *pub_key =
//     "\x30\x49\x02\x42\x01\x4D\x79\x64\xFB\x07\xF4\x85\x11\x09\x1E\xA5"
//     "\x9C\x96\x14\x7D\x75\x52\x8E\x44\x30\x23\xD4\x39\x68\xE2\x4C\xDD"
//     "\x4C\xF2\xD6\x4F\xED\x38\x73\x1D\x23\x57\x2C\xF9\xC9\xA3\x45\x8E"
//     "\xB3\xDC\x7B\xD7\x05\xA4\x9D\x25\x63\xD5\x62\x59\xA2\x2A\x72\xBD"
//     "\xE3\xC6\x7B\x31\xDF\x47\x02\x03\x01\x00\x01";

// int pub_key_len = 75;

#endif //FIREWALL_CONSTANTS_H
