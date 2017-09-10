//
// Roman Sobkuliak 27.8.2017
//

#ifndef NET_MULTI_TRACEROUTE_H
#define NET_MULTI_TRACEROUTE_H

#include "net/Address.h"
#include "net/enums.h"

#include <vector>
#include <chrono>

struct TraceOptions {
    AddressFamily af_if_unknown;
    int probes;
    int break_len;
    int max_ttl;
    int timeout_len;
};

/* Structure holds information about single destination that should be tracerouted. */
struct DestInfo {
    DestInfo() {
        address = Address();
    }
    DestInfo(Address address, std::string dest_str, bool valid) :
        address(address), dest_str(dest_str), address_valid(valid) { }

    Address address;
    std::string dest_str;
    bool address_valid;
};

struct ProbeInfo {
    Address offender;
    IcmpRespStatus icmp_status;
    std::chrono::steady_clock::time_point send_time, recv_time;
    bool did_arrive = false;
};

struct TraceResult {
    std::vector<DestInfo> dest_ip4, dest_ip6, dest_error;
    std::vector<std::vector<std::vector<ProbeInfo>>> probes_info_ip4, probes_info_ip6;
};

void multi_traceroute(std::vector<std::string> dest, TraceOptions options, TraceResult res);

#endif // NET_MULTI_TRACEROUTE_H