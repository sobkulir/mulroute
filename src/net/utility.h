//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_UTILITY_H
#define NET_UTILITY_H

#include "Address.h"

#include <string>

Address get_addr(std::string ip_or_hostname, Address::Family addr_family);

#endif // NET_UTILITY_H