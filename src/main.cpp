#include "multi_traceroute.h"
#include "net/enums.h"

#include <vector>
#include <string>

int main() {
    std::vector<std::string> to_trace = {
        "facebookasdfasdf.com",
        "google.com",
        "halo.si",
        "yahoo.com",
        "hojko.com",
        "klm.nl",
        "vienna.sk",
        "trolo.com",
        "idontknow.sk",
        "cozee.com",
        "jano.sk",
        "as32r.com",
        "no.cz",
    };

    TraceOptions options = {
        af_if_unknown : AddressFamily::Inet,
        probes : 1,
        break_len : 200,
        max_ttl : 1,
        timeout_len : 1000,
        dns_lookup : true,
    };

    TraceResult res;
    res = multi_traceroute(to_trace, options);
}