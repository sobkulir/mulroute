//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_ICMP_HEADER_H
#define NET_ICMP_HEADER_H

#include "enums.h"

#include <netinet/icmp6.h>
#include <cstdint>
#include <vector>

/* Must be at least 8, since the ICMP header is 8 bytes long */
constexpr size_t DEF_ICMP_PACKET_LEN = 16;


/*
 * Class IcmpHeader is an interface for working with ICMPv4/ICMPv6 packets.
 */
class IcmpHeader {
public:
    IcmpHeader() : _family(AddressFamily::Unspec), _length(0) { };
    IcmpHeader(char *buf, size_t buf_length, AddressFamily family);

    char *get_packet_ptr(size_t &length);
    char *get_packet_ptr();
    size_t get_length();
    virtual IcmpRespStatus get_resp_status() = 0;
    virtual u_int16_t get_id() = 0;
    virtual u_int16_t get_seq() = 0;

    virtual void set_type(Icmp6Type type) { };
    virtual void set_type(Icmp4Type type) { };
    virtual void set_code(Icmp6Code code) { };
    virtual void set_code(Icmp4Code code) { };
    virtual void set_id(u_int16_t id) = 0;
    virtual void set_seq(u_int16_t seq) = 0;
    virtual void set_payload(const std::vector<char> &payload_buf, size_t buf_length) = 0;

    /*
     * Method prep_to_send must be called before sending the packet
     * For ICMPv4 it fills the checksum field in the header
     */
    virtual void prep_to_send() { };

protected:
    AddressFamily _family;

    /* This is a buffer that stores the packet in network byte-order */
    std::vector<char> _packet;
    size_t _length;

    void _set_payload(const std::vector<char> &buf, size_t buf_length, size_t hdr_length);
};

/*
 * Icmp6Header is an implementation of IcmpHeader and basically a wrapper over
 * struct icmp6_hdr defined in <netinet/icmp6.h>
 */
class Icmp6Header : public virtual IcmpHeader {
public:
    Icmp6Header();
    Icmp6Header(char *buf, size_t buf_length);
    Icmp6Header(u_int16_t id, u_int16_t seq, std::vector<char> &payload_buf, size_t buf_length);

    IcmpRespStatus get_resp_status() override;
    u_int16_t get_id() override;
    u_int16_t get_seq() override;

    void set_type(Icmp6Type type) override;
    void set_code(Icmp6Code code) override;
    void set_id(u_int16_t id) override;
    void set_seq(u_int16_t seq) override;
    void set_payload(const std::vector<char> &payload_buf, size_t buf_length) override;

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

/*
 * Class Icmp4Header implements IcmpHeader and is a wrapper over
 * struct icmp4_hdr defined above.
 */
class Icmp4Header : public virtual IcmpHeader {
public:
    Icmp4Header();
    Icmp4Header(char *buf, size_t buf_length);
    Icmp4Header(u_int16_t id, u_int16_t seq, std::vector<char> &payload_buf, size_t buf_length);

    IcmpRespStatus get_resp_status() override;
    u_int16_t get_id() override;
    u_int16_t get_seq() override;

    void set_type(Icmp4Type type) override;
    void set_code(Icmp4Code code) override;
    void set_id(u_int16_t id) override;
    void set_seq(u_int16_t seq) override;
    void set_payload(const std::vector<char> &payload_buf, size_t buf_length) override;

    void prep_to_send() override;

private:
    inline struct icmp4_hdr *_hdr_ptr() {
        return (struct icmp4_hdr *) _packet.data();
    }
};

#endif // NET_ICMP_HEADER_H