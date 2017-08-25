//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_ADDRESS_H
#define NET_ADDRESS_H

#include "enums.h"
#include <sys/socket.h>

class Address {
public:
    Address(const sockaddr *info, socklen_t length);

    AddressFamily get_family();
    struct sockaddr *get_ptr(socklen_t &length);

private:
    sockaddr_storage _info;
    socklen_t _length;
};

#endif // NET_ADDRESS_H