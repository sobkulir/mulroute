//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_ICMP_H
#define NET_ICMP_H

#include "enums.h"

#include <netinet/icmp6.h>
#include <cstdint>

#include <vector>

/* Should be at least 8, since the ICMP header is 8 bytes long */
constexpr size_t DEF_PACKET_LEN = 16;

/*
 * Class Icmp is an interface for making ICMPv4/ICMPv6 packets.
 */

class Icmp {
public:
    Icmp() : _family(AddressFamily::Unspec), _length(0) { };
    Icmp(const std::vector<char> &buf, size_t buf_length, AddressFamily family);

    char *get_packet_ptr(size_t &length);
    char *get_packet_ptr();

    virtual void set_type(Icmp6Type type) { };
    virtual void set_type(Icmp4Type type) { };
    virtual void set_code(Icmp6Code code) { };
    virtual void set_code(Icmp4Code code) { };
    virtual void set_id(u_int16_t id) = 0;
    virtual void set_seq(u_int16_t seq) = 0;
    virtual void set_payload(const std::vector<char> &buf, size_t buf_length) = 0;

    /*
     * Method prep_to_send should be called before sending the packet
     * For ICMPv4 it fills the checksum field in the header
     */
    virtual void prep_to_send() { };

protected:
    AddressFamily _family;
    std::vector<char> _packet;
    size_t _length;

    void _set_payload(const std::vector<char> &buf, size_t buf_length, size_t hdr_length);
};

class Icmp6 : public virtual Icmp {
public:
    Icmp6();
    Icmp6(const std::vector<char> &buf, size_t buf_length);

    void set_type(Icmp6Type type) override;
    void set_code(Icmp6Code code) override;
    void set_id(u_int16_t id) override;
    void set_seq(u_int16_t seq) override;
    void set_payload(const std::vector<char> &buf, size_t buf_length) override;

private:
    inline struct icmp6_hdr *_hdr_ptr() {
        return (struct icmp6_hdr *) _packet.data();
    }
};


/*
 * OS X does not have icmphdr struct in <netinet/ip_icmp.h> header file.
 * Therefore icmp4_hdr is basically a copy-paste of this structure.
 */

struct icmp4_hdr
{
  u_int8_t type;        /* message type */
  u_int8_t code;        /* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t id;
      u_int16_t sequence;
    } echo;         /* echo datagram */
    u_int32_t   gateway;    /* gateway address */
    struct
    {
      u_int16_t _unused;
      u_int16_t mtu;
    } frag;         /* path mtu discovery */
  } un;
};


class Icmp4 : public virtual Icmp {
public:
    Icmp4();
    Icmp4(const std::vector<char> &buf, size_t buf_length);

    void set_type(Icmp4Type type) override;
    void set_code(Icmp4Code code) override;
    void set_id(u_int16_t id) override;
    void set_seq(u_int16_t seq) override;
    void set_payload(const std::vector<char> &buf, size_t buf_length) override;

    void prep_to_send() override;

private:
    inline struct icmp4_hdr *_hdr_ptr() {
        return (struct icmp4_hdr *) _packet.data();
    }
};

#endif // NET_ICMP_H