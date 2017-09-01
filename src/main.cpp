#include "multi_traceroute.h"
#include "net/enums.h"

#include <vector>
#include <string>

int main() {
    std::vector<std::string> to_trace = {
        "facebookasdfasdf.com",
        "2001:4860:4860::8888",
        "google.com",
        "idontknow.sk",
        "halo.si",
        "cozee.com",
        "jano.sk",
        "as32r.com",
    };

    TraceOptions options = {
        .af_if_unknown = AddressFamily::Inet,
        .probes = 1,
        .max_ttl = 10,
        .wait_time = 50,
    };

    multi_traceroute(to_trace, options);
}