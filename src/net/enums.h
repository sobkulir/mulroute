//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_ENUM_H
#define NET_ENUM_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <cstdint>

enum class AddressFamily : int {
    Inet = AF_INET,
    Inet6 = AF_INET6,
    Local = AF_LOCAL,
    Route = AF_ROUTE,
    Unspec = AF_UNSPEC,
};

enum class SocketType : int {
    Stream = SOCK_STREAM,
    Datagram = SOCK_DGRAM,
    SeqPacket = SOCK_SEQPACKET,
    Raw = SOCK_RAW,
};

enum class Protocol : int {
    ICMP = IPPROTO_ICMP,
    ICMPV6 = IPPROTO_ICMPV6,
    TCP = IPPROTO_TCP,
    UDP = IPPROTO_UDP,
    SCTP = IPPROTO_SCTP,
};

enum class Icmp6Type : u_int8_t {
    DstUnreach = ICMP6_DST_UNREACH,
    TimeExceeded = ICMP6_TIME_EXCEEDED,
    ParamProb = ICMP6_PARAM_PROB,

    EchoRequest = ICMP6_ECHO_REQUEST,
    EchoReply = ICMP6_ECHO_REPLY,
};

enum class Icmp6Code : u_int8_t {
    NoRoute = ICMP6_DST_UNREACH_NOROUTE,
    Addr = ICMP6_DST_UNREACH_ADDR,
    NoPort = ICMP6_DST_UNREACH_NOPORT,
    Admin = ICMP6_DST_UNREACH_ADMIN,
    NextHeader = ICMP6_PARAMPROB_NEXTHEADER,
};

enum class Icmp4Type : u_int8_t {
    DstUnreach = ICMP_UNREACH,
    TimeExceeded = ICMP_TIMXCEED,
    ParamProb = ICMP_PARAMPROB,

    EchoRequest = ICMP_ECHO,
    EchoReply = ICMP_ECHOREPLY,
};

enum class Icmp4Code : u_int8_t {
    Net = ICMP_UNREACH_NET,
    Host = ICMP_UNREACH_HOST,
    Port = ICMP_UNREACH_PORT,
    NetProhib = ICMP_UNREACH_NET_PROHIB,
    Protocol = ICMP_UNREACH_PROTOCOL,
};

#endif // NET_ENUM_H