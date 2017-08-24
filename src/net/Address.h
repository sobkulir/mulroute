//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_ADDRESS_H
#define NET_ADDRESS_H

#include <sys/socket.h>

class Address {
public:
    enum class Family {
        Inet = AF_INET,
        Inet6 = AF_INET6,
        Unspec = AF_UNSPEC,
    };

    Address(const sockaddr *info, socklen_t length);

    struct sockaddr *get_ptr();

private:
    sockaddr_storage _info;
    socklen_t _length;
};

#endif // NET_ADDRESS_H