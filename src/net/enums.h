//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_ENUM_H
#define NET_ENUM_H

#include <sys/socket.h>
#include <netinet/in.h>

enum class AddressFamily : int {
    Inet = AF_INET,
    Inet6 = AF_INET6,
    Local = AF_LOCAL,
    Route = AF_ROUTE,
    Unspec = AF_UNSPEC,
};

enum class SocketType {
    Stream = SOCK_STREAM,
    Datagram = SOCK_DGRAM,
    SeqPacket = SOCK_SEQPACKET,
    Raw = SOCK_RAW,
};

enum class Protocol {
    ICMP = IPPROTO_ICMP,
    ICMPV6 = IPPROTO_ICMPV6,
    TCP = IPPROTO_TCP,
    UDP = IPPROTO_UDP,
    SCTP = IPPROTO_SCTP,
};
#endif // NET_ENUM_H