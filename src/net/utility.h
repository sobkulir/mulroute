//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_UTILITY_H
#define NET_UTILITY_H

#include "Address.h"
#include "enums.h"

#include <string>
#include <cstdint>

Address get_addr(const std::string ip_or_hostname, AddressFamily addr_family);
uint16_t compute_checksum(uint16_t * addr, int len);

#endif // NET_UTILITY_H