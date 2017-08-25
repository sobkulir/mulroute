//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_UTILITY_H
#define NET_UTILITY_H

#include "Address.h"
#include "enums.h"

#include <string>

Address get_addr(const std::string ip_or_hostname, AddressFamily addr_family);

#endif // NET_UTILITY_H