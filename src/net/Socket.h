//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_SOCKET_H
#define NET_SOCKET_H

#include <sys/socket.h>
#include <netinet/in.h>

class Socket {
public:
    enum class AddressFamily : int {
        Inet = AF_INET,
        Inet6 = AF_INET6,
        Local = AF_LOCAL,
        Route = AF_ROUTE,
    };

    enum class Type {
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

    Socket(AddressFamily addr_family, Type type, Protocol protocol);

    //void send()
private:
    int _socket_FD = -1;
};

#endif  // NET_SOCKET_H