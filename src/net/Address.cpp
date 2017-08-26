//
// Roman Sobkuliak 24.8.2017
//

#include "Address.h"
#include "enums.h"

#include <cstring>

Address::Address(const sockaddr *info, socklen_t length) : _length(length) {
    memcpy(&(this->_info), info, length);
}

AddressFamily Address::get_family() {
    switch (_info.ss_family) {
        case static_cast<int>(AddressFamily::Inet):
            return AddressFamily::Inet;

        case static_cast<int>(AddressFamily::Inet6):
            return AddressFamily::Inet6;

        default:
            return AddressFamily::Unspec;
    }
}

struct sockaddr *Address::get_sockaddr_ptr() {
    return (struct sockaddr *) &_info;
}

size_t Address::get_length() {
    return _length;
}