//
// Roman Sobkuliak 24.8.2017
//

#include "utility.h"
#include "Address.h"
#include "GaiException.h"

#include <netdb.h>
#include <sys/socket.h>
#include <string>
#include <cstring>

Address get_addr(std::string ip_or_hostname, Address::Family addr_family) {
    int status;
    struct addrinfo hints, *res = nullptr;

    memset (&hints, 0, sizeof(hints) );
    hints.ai_family = static_cast<int>(addr_family);

    status = getaddrinfo(ip_or_hostname.c_str(), nullptr, &hints, &res);
    if (status) {
        throw GaiException(status);
    }

    // Take first result
    Address addr_ret(res->ai_addr, res->ai_addrlen);

    freeaddrinfo (res);

    return addr_ret;
}
