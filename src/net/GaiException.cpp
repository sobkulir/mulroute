//
// Roman Sobkuliak 24.8.2017
//

#include "GaiException.h"
#include <netdb.h>

const char *GaiException::what() const noexcept {
    return gai_strerror(code_);
}

const int GaiException::code() const noexcept {
    return code_;
}
