//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_ADDRESS_H
#define NET_ADDRESS_H

#include "enums.h"

#include <sys/socket.h>
#include <string>

class Address {
public:
    Address(const sockaddr *info, socklen_t length);

    AddressFamily get_family();
    struct sockaddr *get_sockaddr_ptr();
    socklen_t get_length();
    std::string get_hostname();

    std::string retrieve_hostname();

private:
    sockaddr_storage _info;
    socklen_t _length;

    std::string _hostname;
};

#endif // NET_ADDRESS_H