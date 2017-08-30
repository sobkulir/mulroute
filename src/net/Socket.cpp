//
// Roman Sobkuliak 24.8.2017
//

#include "Socket.h"
#include "enums.h"
#include "Address.h"

#include <system_error>
#include <sys/socket.h>
#include <unistd.h>
#include <stdexcept>

Socket::Socket(AddressFamily addr_family, SocketType type, Protocol protocol) : _family(addr_family) {
    // socket() arguments are of type int
    _socket_FD = socket(
        static_cast<int>(addr_family),
        static_cast<int>(type),
        static_cast<int>(protocol)
    );

    if (_socket_FD == -1) {
        throw std::system_error(errno, std::system_category());
    }
}

Socket::Socket::~Socket() {
    close(_socket_FD);
}

int Socket::send(char *send_buf, size_t buf_length, const Address &to) {
    int status;

    status = sendto(_socket_FD, send_buf, buf_length, 0, to.get_sockaddr_ptr(), to.get_length());
    if (status == -1) {
        throw std::system_error(errno, std::system_category());
    }

    return status;
}

void Socket::set_ttl(int ttl) {
    int status = 0;

    switch (_family) {
        case AddressFamily::Inet:
            status = setsockopt(_socket_FD, IPPROTO_IP, IP_TTL, &ttl, sizeof (int));
            break;
        case AddressFamily::Inet6:
            status = setsockopt(_socket_FD, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof (int));
            break;
        default:
            throw std::runtime_error("Unhandled family in set_ttl method");
    }

    if (status == -1) {
        throw std::system_error(errno, std::system_category());
    }
}