//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_UTILITY_H
#define NET_UTILITY_H

#include "Address.h"
#include "enums.h"

#include <string>
#include <cstdint>

Address str_to_address(const std::string ip_or_hostname, AddressFamily af_if_unknown);
uint16_t compute_checksum(uint16_t * addr, int len);
AddressFamily ip_version(const std::string ip_address);

#endif // NET_UTILITY_H
