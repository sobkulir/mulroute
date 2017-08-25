//
// Roman Sobkuliak 24.8.2017
//

#include "Socket.h"
#include "enums.h"

#include <system_error>
#include <sys/socket.h>

Socket::Socket(AddressFamily addr_family, SocketType type, Protocol protocol) {
    // Casting is needed because socket() arguments are of type int
    _socket_FD = socket(
        static_cast<int>(addr_family),
        static_cast<int>(type),
        static_cast<int>(protocol)
    );

    if (_socket_FD == -1) {
        throw std::system_error(errno, std::system_category());
    }
}
