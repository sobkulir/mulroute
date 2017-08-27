//
// Roman Sobkuliak 24.8.2017
//

#include "utility.h"
#include "Address.h"
#include "GaiException.h"
#include "enums.h"

#include <netdb.h>
#include <sys/socket.h>
#include <string>
#include <cstring>
#include <cstdint>

Address get_addr(const std::string ip_or_hostname, AddressFamily addr_family) {
    int status;
    struct addrinfo hints, *res = nullptr;

    memset(&hints, 0, sizeof(hints) );
    hints.ai_family = static_cast<int>(addr_family);

    status = getaddrinfo(ip_or_hostname.c_str(), nullptr, &hints, &res);
    if (status) {
        throw GaiException(status);
    }

    // Take first result
    Address addr_ret(res->ai_addr, res->ai_addrlen);

    freeaddrinfo (res);

    return addr_ret;
}

/*
 * Function returns checksum in network byte order
 *
 * The Internet checksum is the one's complement of the one's complement sum of
 * the 16-bit values to be checksummed. If the data length is an odd number,
 * then 1 byte of 0 is logically appended to the end of the data, just for the
 * checksum computation.
 *
 * This function is taken from the public domain version of ping by Mike Muuss.
 */

uint16_t compute_checksum(uint16_t * addr, int len) {
    int     nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        * (unsigned char *) (&answer) = * (unsigned char *) w;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);     /* add carry */
    answer = ~sum;     /* truncate to 16 bits */
    return (answer);
}