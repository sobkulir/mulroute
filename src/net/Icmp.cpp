//
// Roman Sobkuliak 24.8.2017
//

#include "Icmp.h"
#include "enums.h"
#include "utility.h"

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <cstring>
#include <vector>
#include <cstdint>

/*
 * Icmp
 */

Icmp::Icmp(const std::vector<char> &buf, size_t buf_length, AddressFamily family) {
    _packet = std::vector<char>(buf_length, 0);
    memcpy(_packet.data(), buf.data(), buf_length);

    _length = buf_length;
    _family = family;
}

char *Icmp::get_packet_ptr(size_t &length) {
    length = _length;
    return _packet.data();
}

char *Icmp::get_packet_ptr() {
    return _packet.data();
}

void Icmp::_set_payload(const std::vector<char> &buf, size_t buf_length, size_t hdr_length) {
    size_t new_length = buf_length + hdr_length;
    if (new_length > _packet.size()) {
        _packet.resize(new_length);
    }

    memcpy(_packet.data() + hdr_length, buf.data(), buf_length);
    _length = new_length;
}

/*
 *  Icmp6
 */

Icmp6::Icmp6() {
    _packet = std::vector<char>(DEF_PACKET_LEN, 0);
    _length = sizeof(struct icmp6_hdr);
    _family = AddressFamily::Inet6;
}

Icmp6::Icmp6(const std::vector<char> &buf, size_t buf_length) :
    Icmp(buf, buf_length, AddressFamily::Inet6) { }

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
    Icmp::_set_payload(buf, buf_length, sizeof(struct icmp6_hdr));
}


/*
 * Icmp4
 */

Icmp4::Icmp4() {
    _packet = std::vector<char>(DEF_PACKET_LEN, 0);
    _length = sizeof(struct icmp4_hdr);
    _family = AddressFamily::Inet;
}

Icmp4::Icmp4(const std::vector<char> &buf, size_t buf_length) :
    Icmp(buf, buf_length, AddressFamily::Inet6) { }


void Icmp4::set_type(Icmp4Type type) {
    _hdr_ptr()->type = static_cast<u_int8_t>(type);
}

void Icmp4::set_code(Icmp4Code code) {
    _hdr_ptr()->code = static_cast<u_int8_t>(code);
}

void Icmp4::set_id(u_int16_t id) {
    _hdr_ptr()->un.echo.id = htons(id);
}

void Icmp4::set_seq(u_int16_t seq) {
    _hdr_ptr()->un.echo.sequence = htons(seq);
}

void Icmp4::set_payload(const std::vector<char> &buf, size_t buf_length) {
    Icmp::_set_payload(buf, buf_length, sizeof(struct icmp4_hdr));
}

void Icmp4::prep_to_send() {
    _hdr_ptr()->checksum = htons(
        compute_checksum((u_int16_t *) Icmp::get_packet_ptr(), _length));
}
