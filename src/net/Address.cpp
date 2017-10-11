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
#include <netinet/in.h>
#include <arpa/inet.h>

Address::Address() : length_(sizeof(struct sockaddr_storage)) {

}

Address::Address(const sockaddr *info, socklen_t length) : length_(length) {
    memcpy(&(this->info_), info, length);
}

AddressFamily Address::get_family() const {
    switch (info_.ss_family) {
        case static_cast<int>(AddressFamily::Inet):
            return AddressFamily::Inet;

        case static_cast<int>(AddressFamily::Inet6):
            return AddressFamily::Inet6;

        default:
            return AddressFamily::Unspec;
    }
}

struct sockaddr *Address::get_sockaddr_ptr() const {
    return (struct sockaddr *) &info_;
}

socklen_t Address::get_length() const {
    return length_;
}

std::string Address::get_hostname() const {
    return hostname_;
}

std::string Address::get_ip_str() const {
    // IPv6 is 128 bytes long
    int MAX_IP_LEN = 129;
    char ip_str[MAX_IP_LEN];

    AddressFamily af = get_family();
    void *addr_ptr;

    if (af == AddressFamily::Inet) {
        addr_ptr = (void *) &((struct sockaddr_in *) get_sockaddr_ptr())->sin_addr;
    } else {
        addr_ptr = (void *) &((struct sockaddr_in6 *) get_sockaddr_ptr())->sin6_addr;
    }

    if (inet_ntop(static_cast<int>(af), addr_ptr, ip_str , MAX_IP_LEN) == nullptr) {
        return std::string();
    }

    return ip_str;
}

void Address::set_length(int length) {
    length_ = length;
}

void Address::set_hostname(std::string hostname) {
    hostname_ = hostname;
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

    hostname_ = std::string(hostname_buf);

    return hostname_;
}
