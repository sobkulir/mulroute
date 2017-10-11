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
#include <sys/select.h>
#include <sys/time.h>

Socket::Socket(AddressFamily addr_family, SocketType type, Protocol protocol) : family_(addr_family) {
    // socket() arguments are of type int
    socket_FD_ = socket(
        static_cast<int>(addr_family),
        static_cast<int>(type),
        static_cast<int>(protocol)
    );

    if (socket_FD_ == -1) {
        throw std::system_error(errno, std::generic_category());
    }
}

Socket::Socket::~Socket() {
    close(socket_FD_);
}

int Socket::send(char *send_buf, size_t buf_length, const Address &to) {
    int status;

    status = sendto(socket_FD_, send_buf, buf_length, 0, to.get_sockaddr_ptr(), to.get_length());

    if (status == -1) {
        throw std::system_error(errno, std::generic_category());
    }

    return status;
}

int Socket::recv(char *recv_buf, size_t buf_length, Address &from) {
    int status;
    socklen_t address_length = from.get_length();

    status = recvfrom(socket_FD_, recv_buf, buf_length, 0, from.get_sockaddr_ptr(), &address_length);

    if (status == -1) {
        throw std::system_error(errno, std::generic_category());
    }

    // from contains offender's address, but the length attribute needs to be set
    from.set_length(address_length);

    return status;
}

bool Socket::wait_for_recv(int seconds, int microseconds) {
    timeval tv = {};
    tv.tv_sec = seconds;
    tv.tv_usec = microseconds;

    fd_set set;
    FD_ZERO(&set);
    FD_SET(socket_FD_, &set);

    if (select(socket_FD_ + 1, &set, nullptr, nullptr, &tv) == -1) {
        throw std::system_error(std::error_code(errno, std::generic_category()));
    }

    return static_cast<bool>(FD_ISSET(socket_FD_, &set));
}


void Socket::set_ttl(int ttl) {
    int status = 0;

    switch (family_) {
        case AddressFamily::Inet:
            status = setsockopt(socket_FD_, IPPROTO_IP, IP_TTL, &ttl, sizeof (int));
            break;
        case AddressFamily::Inet6:
            status = setsockopt(socket_FD_, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof (int));
            break;
        default:
            throw std::runtime_error("Unhandled family in set_ttl method");
    }

    if (status == -1) {
        throw std::system_error(errno, std::generic_category());
    }
}
