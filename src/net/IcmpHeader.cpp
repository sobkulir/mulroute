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

IcmpHeader::IcmpHeader(char *buf, size_t buf_length, AddressFamily family) {
    packet_ = std::vector<char>(buf_length, 0);
    memcpy(packet_.data(), buf, buf_length);
    length_ = buf_length;
    family_ = family;
}

char *IcmpHeader::get_packet_ptr(size_t &length) {
    length = length_;
    return packet_.data();
}

char *IcmpHeader::get_packet_ptr() {
    return packet_.data();
}

void IcmpHeader::set_payload_(const std::vector<char> &payload_buf, size_t buf_length, size_t hdr_length) {
    size_t new_length = buf_length + hdr_length;
    if (new_length > packet_.size()) {
        packet_.resize(new_length);
    }

    memcpy(packet_.data() + hdr_length, payload_buf.data(), buf_length);
    length_ = new_length;
}

size_t IcmpHeader::get_length() {
    return length_;
}

/*
 *  Icmp6Header
 */

Icmp6Header::Icmp6Header() {
    packet_ = std::vector<char>(DEF_ICMP_PACKET_LEN, 0);
    length_ = sizeof(struct icmp6_hdr);
    family_ = AddressFamily::Inet6;
}

Icmp6Header::Icmp6Header(char *buf, size_t buf_length) :
    IcmpHeader(buf, buf_length, AddressFamily::Inet6) { }

Icmp6Header::Icmp6Header(u_int16_t id, u_int16_t seq, std::vector<char> &payload_buf, size_t buf_length) : Icmp6Header() {
    set_type(Icmp6Type::EchoRequest);
    set_id(id);
    set_seq(seq);
    set_payload(payload_buf, buf_length);
}

IcmpRespStatus Icmp6Header::get_resp_status() {
    switch (Icmp6Type(hdr_ptr_()->icmp6_type)) {
        case Icmp6Type::DstUnreach:
            switch (Icmp6Code(hdr_ptr_()->icmp6_code)) {
                case Icmp6Code::NoRoute: return IcmpRespStatus::NetworkUnreachable;
                case Icmp6Code::Addr: return IcmpRespStatus::HostUnreachable;
                case Icmp6Code::NoPort: return IcmpRespStatus::PortUnreachable;

                case Icmp6Code::Admin: return IcmpRespStatus::AdminProhibited;
            }
        case Icmp6Type::ParamProb:
            switch (Icmp6Code(hdr_ptr_()->icmp6_code)) {
                case Icmp6Code::NextHeader: return IcmpRespStatus::ProtocolUnreachable;
                default: return IcmpRespStatus::Unknown;
            }
        case Icmp6Type::TimeExceeded: return IcmpRespStatus::TimeExceeded;
        case Icmp6Type::EchoReply: return IcmpRespStatus::EchoReply;
        default: return IcmpRespStatus::Unknown;
    }

    return IcmpRespStatus::Unknown;
}

u_int16_t Icmp6Header::get_id() {
    return ntohs(hdr_ptr_()->icmp6_id);
}

u_int16_t Icmp6Header::get_seq() {
    return ntohs(hdr_ptr_()->icmp6_seq);
}

void Icmp6Header::set_type(Icmp6Type type) {
    hdr_ptr_()->icmp6_type = static_cast<u_int8_t>(type);
}

void Icmp6Header::set_code(Icmp6Code code) {
    hdr_ptr_()->icmp6_code = static_cast<u_int8_t>(code);
}

void Icmp6Header::set_id(u_int16_t id) {
    hdr_ptr_()->icmp6_id = htons(id);
}

void Icmp6Header::set_seq(u_int16_t seq) {
    hdr_ptr_()->icmp6_seq = htons(seq);
}

void Icmp6Header::set_payload(const std::vector<char> &payload_buf, size_t buf_length) {
    IcmpHeader::set_payload_(payload_buf, buf_length, sizeof(struct icmp6_hdr));
}


/*
 * Icmp4Header
 */

Icmp4Header::Icmp4Header() {
    packet_ = std::vector<char>(DEF_ICMP_PACKET_LEN, 0);
    length_ = sizeof(struct icmp4_hdr);
    family_ = AddressFamily::Inet;
}

Icmp4Header::Icmp4Header(char *buf, size_t buf_length) :
    IcmpHeader(buf, buf_length, AddressFamily::Inet6) { }

Icmp4Header::Icmp4Header(u_int16_t id, u_int16_t seq, std::vector<char> &payload_buf, size_t buf_length) : Icmp4Header() {
    set_type(Icmp4Type::EchoRequest);
    set_id(id);
    set_seq(seq);
    set_payload(payload_buf, buf_length);
}

IcmpRespStatus Icmp4Header::get_resp_status() {
    switch (Icmp4Type(hdr_ptr_()->type)) {
        case Icmp4Type::DstUnreach:
            switch (Icmp4Code(hdr_ptr_()->code)) {
                case Icmp4Code::Net: return IcmpRespStatus::NetworkUnreachable;
                case Icmp4Code::Host: return IcmpRespStatus::HostUnreachable;
                case Icmp4Code::Protocol: return IcmpRespStatus::ProtocolUnreachable;
                case Icmp4Code::Port: return IcmpRespStatus::PortUnreachable;

                case Icmp4Code::NetProhib:
                case Icmp4Code::HostProhib:
                case Icmp4Code::FilterProhib: return IcmpRespStatus::AdminProhibited;
                default:  return IcmpRespStatus::Unknown;
            }
        case Icmp4Type::TimeExceeded: return IcmpRespStatus::TimeExceeded;
        case Icmp4Type::EchoReply: return IcmpRespStatus::EchoReply;
        default: return IcmpRespStatus::Unknown;
    }

    return IcmpRespStatus::Unknown;
}

u_int16_t Icmp4Header::get_id() {
    return ntohs(hdr_ptr_()->un.echo.id);
}

u_int16_t Icmp4Header::get_seq() {
    return ntohs(hdr_ptr_()->un.echo.sequence);
}

void Icmp4Header::set_type(Icmp4Type type) {
    hdr_ptr_()->type = static_cast<u_int8_t>(type);
}

void Icmp4Header::set_code(Icmp4Code code) {
    hdr_ptr_()->code = static_cast<u_int8_t>(code);
}

void Icmp4Header::set_id(u_int16_t id) {
    hdr_ptr_()->un.echo.id = htons(id);
}

void Icmp4Header::set_seq(u_int16_t seq) {
    hdr_ptr_()->un.echo.sequence = htons(seq);
}

void Icmp4Header::set_payload(const std::vector<char> &payload_buf, size_t buf_length) {
    IcmpHeader::set_payload_(payload_buf, buf_length, sizeof(struct icmp4_hdr));
}

void Icmp4Header::prep_to_send() {
    /* Checksum field must be set to zero before checksum computation */
    hdr_ptr_()->checksum = 0;

    /* compute_checksum returns checksum in a network byte-order */
    hdr_ptr_()->checksum =
        compute_checksum((u_int16_t *) IcmpHeader::get_packet_ptr(), length_);
}
