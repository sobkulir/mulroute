//
// Roman Sobkuliak 24.8.2017
//

#include "Icmp.h"
#include "enums.h"

#include <netinet/in.h>
#include <cstring>
#include <vector>

Icmp6::Icmp6() {
    _packet = std::vector<char>(DEF_PACKET_LEN, 0);
    _length = sizeof(struct icmp6_hdr);

    _family = AddressFamily::Inet6;
}

Icmp6::Icmp6(const std::vector<char> &buf, size_t buf_length) {
    _packet = std::vector<char>(buf_length, 0);
    memcpy(_packet.data(), buf.data(), buf_length);
}

char *Icmp6::get_packet_ptr(size_t &length) {
    length = _length;
    return _packet.data();
}

void Icmp6::set_type(Icmp6Type type) {
    _hdr_ptr()->icmp6_type = static_cast<u_int8_t>(type);
}

void Icmp6::set_code(Icmp6Code code) {
    _hdr_ptr()->icmp6_code = static_cast<u_int8_t>(code);
}

void Icmp6::set_id(u_int16_t id) {
    _hdr_ptr()->icmp6_id = htons(id);
}

void Icmp6::set_seq(u_int16_t seq) {
    _hdr_ptr()->icmp6_seq = htons(seq);
}

void Icmp6::set_payload(const std::vector<char> &buf, size_t buf_length) {
    size_t new_length = buf_length + sizeof(struct icmp6_hdr);
    if (new_length > _packet.size()) {
        _packet.resize(new_length);
    }

    memcpy(_packet.data() + sizeof(struct icmp6_hdr), buf.data(), buf_length);
    _length = new_length;
}