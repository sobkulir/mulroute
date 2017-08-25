//
// Roman Sobkuliak 24.8.2017
//

#include "Address.h"
#include <cstring>

Address::Address(const sockaddr *info, socklen_t length) : _length(length) {
    memcpy(&(this->_info), info, length);
}

struct sockaddr *Address::get_ptr(socklen_t &length) {
    length = _length;
    return (struct sockaddr *) &_info;
}