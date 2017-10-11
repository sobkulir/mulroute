//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_ADDRESS_H
#define NET_ADDRESS_H

#include "enums.h"

#include <sys/socket.h>
#include <string>

class Address {
public:
    Address();
    Address(const sockaddr *info, socklen_t length);

    AddressFamily get_family() const;
    struct sockaddr *get_sockaddr_ptr() const;
    socklen_t get_length() const;
    std::string get_hostname() const;
    std::string get_ip_str() const;

    void set_length(int length);
    void set_hostname(std::string hostname);

    /* This method does a dns lookup and fills hostname_ */
    std::string retrieve_hostname();

private:
    sockaddr_storage info_;
    socklen_t length_;

    std::string hostname_;
};

#endif // NET_ADDRESS_H
