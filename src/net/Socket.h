//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_SOCKET_H
#define NET_SOCKET_H

#include "enums.h"
#include "Address.h"

class Socket {
public:
    Socket(AddressFamily addr_family, SocketType type, Protocol protocol);

    int send(char *send_buf, size_t buf_length, const Address &to);
    int recv(char *recv_buf, size_t buf_length, Address &from);
    bool wait_for_recv(int seconds);

    void set_ttl(int ttl);

    virtual ~Socket();
private:
    int _socket_FD = -1;
    AddressFamily _family;
};

#endif  // NET_SOCKET_H