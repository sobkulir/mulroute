//
// Roman Sobkuliak 27.8.2017
//

#ifndef NET_MULTI_TRACEROUTE_H
#define NET_MULTI_TRACEROUTE_H

#include "net/Address.h"

#include <vector>

struct TraceOptions {
    AddressFamily af_if_unknown;
    int probes;
    int max_ttl;
};

class Probe {
public:
    Address address;
    // rtt time
};

std::vector<std::vector<Probe>> multi_traceroute(std::vector<std::string> dest, TraceOptions options);

#endif // NET_MULTI_TRACEROUTE_H