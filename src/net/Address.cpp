//
// Roman Sobkuliak 24.8.2017
//

#include "Address.h"
#include "enums.h"
#include "GaiException.h"

#include <cstring>
#include <string>
#include <netdb.h>
#include <sys/socket.h>

Address::Address() : _length(sizeof(struct sockaddr_storage)) {

}

Address::Address(const sockaddr *info, socklen_t length) : _length(length) {
    memcpy(&(this->_info), info, length);
}

AddressFamily Address::get_family() const {
    switch (_info.ss_family) {
        case static_cast<int>(AddressFamily::Inet):
            return AddressFamily::Inet;

        case static_cast<int>(AddressFamily::Inet6):
            return AddressFamily::Inet6;

        default:
            return AddressFamily::Unspec;
    }
}

struct sockaddr *Address::get_sockaddr_ptr() const {
    return (struct sockaddr *) &_info;
}

socklen_t Address::get_length() const {
    return _length;
}

std::string Address::get_hostname() const {
    return _hostname;
}

void Address::set_length(int length) {
    _length = length;
}

std::string Address::retrieve_hostname() {
    /* NI_MAXHOST is a constant defined in <netdb.h> */
    char hostname_buf[NI_MAXHOST];

    int status = getnameinfo(
        get_sockaddr_ptr(),
        get_length(),
        hostname_buf,
        NI_MAXHOST,
        nullptr,
        0,
        0);

    if (status) {
        throw GaiException(status);
    }

    _hostname = std::string(hostname_buf);

    return _hostname;
}