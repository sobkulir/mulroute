//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_ICMP_H
#define NET_ICMP_H

#include "enums.h"

#include <netinet/icmp6.h>
#include <cstdint>

#include <vector>

// Should be at least 8, since the ICMP header is 8 bytes long
constexpr size_t DEF_PACKET_LEN = 16;

class Icmp {
public:
    // Icmp4/Icmp6::Type and Code are defined below, so we can not use them

    virtual char *get_packet_ptr(size_t &length) = 0;

    virtual void set_type(Icmp6Type type) { };
   // virtual void set_type(Icmp4Type type) { };
    virtual void set_code(Icmp6Code code) { };
    //virtual void set_code(Icmp4Code code) { };
    virtual void set_id(u_int16_t id) = 0;
    virtual void set_seq(u_int16_t seq) = 0;
    virtual void set_payload(const std::vector<char> &buf, size_t buf_length) = 0;

    //virtual void cksum() = 0;

protected:
    AddressFamily _family;
};

class Icmp6 : public virtual Icmp {
public:
    Icmp6();
    Icmp6(const std::vector<char> &buf, size_t buf_length);

    char *get_packet_ptr(size_t &length) override;

    void set_type(Icmp6Type type) override;
    void set_code(Icmp6Code code) override;
    void set_id(u_int16_t id) override;
    void set_seq(u_int16_t seq) override;
    void set_payload(const std::vector<char> &buf, size_t buf_length) override;


private:
    std::vector<char> _packet;
    size_t _length;

    inline struct icmp6_hdr *_hdr_ptr() {
        return (struct icmp6_hdr *) _packet.data();
    }
};

#endif // NET_ICMP_H