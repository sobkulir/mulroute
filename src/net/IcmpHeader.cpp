//
// Roman Sobkuliak 24.8.2017
//

#include "IcmpHeader.h"
#include "enums.h"
#include "utility.h"

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <cstring>
#include <vector>
#include <cstdint>

/*
 * IcmpHeader
 */

IcmpHeader::IcmpHeader(const std::vector<char> &buf, size_t buf_length, AddressFamily family) {
    _packet = std::vector<char>(buf_length, 0);
    memcpy(_packet.data(), buf.data(), buf_length);
    _length = buf_length;
    _family = family;
}

char *IcmpHeader::get_packet_ptr(size_t &length) {
    length = _length;
    return _packet.data();
}

char *IcmpHeader::get_packet_ptr() {
    return _packet.data();
}

void IcmpHeader::_set_payload(const std::vector<char> &payload_buf, size_t buf_length, size_t hdr_length) {
    size_t new_length = buf_length + hdr_length;
    if (new_length > _packet.size()) {
        _packet.resize(new_length);
    }

    memcpy(_packet.data() + hdr_length, payload_buf.data(), buf_length);
    _length = new_length;
}

size_t IcmpHeader::get_length() {
    return _length;
}
/*
 *  Icmp6Header
 */

Icmp6Header::Icmp6Header() {
    _packet = std::vector<char>(DEF_ICMP_PACKET_LEN, 0);
    _length = sizeof(struct icmp6_hdr);
    _family = AddressFamily::Inet6;
}

Icmp6Header::Icmp6Header(const std::vector<char> &buf, size_t buf_length) :
    IcmpHeader(buf, buf_length, AddressFamily::Inet6) { }

Icmp6Header::Icmp6Header(u_int16_t id, u_int16_t seq, std::vector<char> &payload_buf, size_t buf_length) : Icmp6Header() {
    set_type(Icmp6Type::EchoRequest);
    set_id(id);
    set_seq(seq);
    set_payload(payload_buf, buf_length);
}

void Icmp6Header::set_type(Icmp6Type type) {
    _hdr_ptr()->icmp6_type = static_cast<u_int8_t>(type);
}

void Icmp6Header::set_code(Icmp6Code code) {
    _hdr_ptr()->icmp6_code = static_cast<u_int8_t>(code);
}

void Icmp6Header::set_id(u_int16_t id) {
    _hdr_ptr()->icmp6_id = htons(id);
}

void Icmp6Header::set_seq(u_int16_t seq) {
    _hdr_ptr()->icmp6_seq = htons(seq);
}

void Icmp6Header::set_payload(const std::vector<char> &payload_buf, size_t buf_length) {
    IcmpHeader::_set_payload(payload_buf, buf_length, sizeof(struct icmp6_hdr));
}


/*
 * Icmp4Header
 */

Icmp4Header::Icmp4Header() {
    _packet = std::vector<char>(DEF_ICMP_PACKET_LEN, 0);
    _length = sizeof(struct icmp4_hdr);
    _family = AddressFamily::Inet;
}

Icmp4Header::Icmp4Header(const std::vector<char> &buf, size_t buf_length) :
    IcmpHeader(buf, buf_length, AddressFamily::Inet6) { }

Icmp4Header::Icmp4Header(u_int16_t id, u_int16_t seq, std::vector<char> &payload_buf, size_t buf_length) : Icmp4Header() {
    set_type(Icmp4Type::EchoRequest);
    set_id(id);
    set_seq(seq);
    set_payload(payload_buf, buf_length);
}

void Icmp4Header::set_type(Icmp4Type type) {
    _hdr_ptr()->type = static_cast<u_int8_t>(type);
}

void Icmp4Header::set_code(Icmp4Code code) {
    _hdr_ptr()->code = static_cast<u_int8_t>(code);
}

void Icmp4Header::set_id(u_int16_t id) {
    _hdr_ptr()->un.echo.id = htons(id);
}

void Icmp4Header::set_seq(u_int16_t seq) {
    _hdr_ptr()->un.echo.sequence = htons(seq);
}

void Icmp4Header::set_payload(const std::vector<char> &payload_buf, size_t buf_length) {
    IcmpHeader::_set_payload(payload_buf, buf_length, sizeof(struct icmp4_hdr));
}

void Icmp4Header::prep_to_send() {
    /* Checksum field must be set to zero for proper checksum computation */
    _hdr_ptr()->checksum = 0;

    /* compute_checksum returns checksum in network byte order */
    _hdr_ptr()->checksum =
        compute_checksum((u_int16_t *) IcmpHeader::get_packet_ptr(), _length);
}
