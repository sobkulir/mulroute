//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_SOCKET_H
#define NET_SOCKET_H

#include "enums.h"

class Socket {
public:
    Socket(AddressFamily addr_family, SocketType type, Protocol protocol);

    virtual ~Socket();
private:
    int _socket_FD = -1;
};

#endif  // NET_SOCKET_H