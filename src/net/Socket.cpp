//
// Roman Sobkuliak 24.8.2017
//

#include "Socket.h"
#include "enums.h"
#include "Address.h"

#include <system_error>
#include <sys/socket.h>
#include <unistd.h>

Socket::Socket(AddressFamily addr_family, SocketType type, Protocol protocol) {
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

int Socket::send(char *send_buf, size_t buf_length, Address &to) {
    int status;

    status = sendto(_socket_FD, send_buf, buf_length, 0, to.get_sockaddr_ptr(), to.get_length());
    if (status == -1) {
        throw std::system_error(errno, std::system_category());
    }

    return status;
}