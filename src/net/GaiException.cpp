//
// Roman Sobkuliak 24.8.2017
//

#include "GaiException.h"
#include <netdb.h>

const char *GaiException::what() const noexcept {
    return gai_strerror(_code);
}

const int GaiException::code() const noexcept {
    return _code;
}