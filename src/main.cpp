#include "multi_traceroute.h"
#include "net/enums.h"

#include <vector>
#include <string>
#include <cstdio>
#include <chrono>
#include <cstdlib>

using std::vector;

void print_routes(vector<vector<vector<ProbeInfo>>> &probes_info, vector<DestInfo> &dest, TraceOptions options) {
    // TTLs of last packet that sucessfully returned for each destination
    vector<int> last_arrived(dest.size());

    for (size_t d = 0; d < probes_info.size(); ++d) {
        for (size_t ttl = 0; ttl < probes_info[d].size(); ++ttl) {
            for (const auto &probe : probes_info[d][ttl]) {
                if (probe.did_arrive) {
                    last_arrived[d] = ttl + options.start_ttl;
                }
            }
        }
    }

    for (size_t d = 0; d < probes_info.size(); ++d) {
        printf("traceroute to %s (%s), %d hops max\n", dest[d].dest_str.c_str(), dest[d].address.get_ip_str().c_str(), options.max_ttl);

        bool dest_reached = false;

        for (size_t ttl = 0; ttl + options.start_ttl <= last_arrived[d]; ++ttl) {
            printf("%2zu", ttl + options.start_ttl);

            std::string last_ip = "";

            for (size_t p = 0; p < probes_info[d][ttl].size(); ++p) {
                const ProbeInfo &probe = probes_info[d][ttl][p];

                if (!probe.did_arrive) {
                    printf("  *");
                    continue;
                }

                std::string ip = probe.offender.get_ip_str();
                int rtt = std::chrono::duration_cast<std::chrono::microseconds>(probe.recv_time - probe.send_time).count();

                if (ip != last_ip) {
                    if (p != 0) {
                        printf("\n  ");
                    }

                    if (options.map_ip_to_host) {
                        printf("  %s (%s)", probe.offender.get_hostname().c_str(), ip.c_str());
                    } else {
                        printf("  %s", ip.c_str());
                    }
                }

                printf("  %1.3f ms", static_cast<double>(rtt) / 1000);

                switch (probe.icmp_status) {
                    case IcmpRespStatus::HostUnreachable:
                        printf(" !H");
                        dest_reached = true;
                        break;

                    case IcmpRespStatus::NetworkUnreachable:
                        printf(" !N");
                        dest_reached = true;
                        break;

                    case IcmpRespStatus::ProtocolUnreachable:
                        printf(" !P");
                        dest_reached = true;
                        break;

                    case IcmpRespStatus::AdminProhibited:
                        printf(" !X");
                        dest_reached = true;
                        break;
                    case IcmpRespStatus::EchoReply:
                        dest_reached = true;
                        break;

                    default: break;
                }

                last_ip = ip;
            }

            printf("\n");
        }

        /*
         * Signal that we didn't reach the destination
         * Eg.:
         *      16  et-17-1.fab1-1-gdc.ne1.yahoo.com (98.138.0.79)  223.473 ms  225.312 ms
         *      17  po-10.bas1-7-prd.ne1.yahoo.com (98.138.240.6)  225.251 ms  226.105 ms
         *       .  * * *
         *       .  * * *
         *      21  * * *
         */
        if (!dest_reached && last_arrived[d] < options.max_ttl) {
            int dotted = std::min(options.max_ttl - (last_arrived[d] + 1) - 1, 2);

            for (int i = 0; i < dotted; ++i) {
                printf(" .  * * *\n");
            }

            printf("%2d  * * *\n", options.max_ttl);
        }

        // Don't print newline after last destination
        if (d + 1 < dest.size()) {
            printf("\n");
        }
    }
}
/*
TraceOptions get_args(int argc, char *const argv[]) {
    // Defaults
    TraceOptions options = {};
    conf.ttl_start = 1;
    conf.ttl_max = 30;
    conf.port = "33434";

    int opt;
    while ((opt = getopt(argc, argv, "f:m:p:")) != -1) {
        switch (opt) {
            case 'f':
                conf.ttl_start = std::stoi(optarg);
                break;

            case 'm':
                conf.ttl_max = std::stoi(optarg);
                break;

            case 'p':
                conf.port = optarg;
                break;

            default:
                break;
        }
    }

    if (optind < argc) {
        conf.ip = argv[optind];
    }

    return conf;
}
*/
int main() {
    std::vector<std::string> to_trace = {
        "facebookasdfasdf.com",
        "nah.com",
        "yahoo.com",
        "halo.si",
        "yahoo.com",
        "hojko.com",
        "klm.nl",
        "zuzka.sk",
        "google.sk",
        "cozee.com",
        "jano.sk",
        "as32r.com",
        "no.cz",
    };

    TraceOptions options = {
        af_if_unknown : AddressFamily::Inet,
        probes : 2,
        sendwait : 50,
        start_ttl : 10,
        max_ttl : 25,
        timeout_len : 1000,
        map_ip_to_host : true,
    };

    TraceResult res;
    res = multi_traceroute(to_trace, options);

    print_routes(res.probes_info_ip4, res.dest_ip4, options);
    print_routes(res.probes_info_ip6, res.dest_ip6, options);
}