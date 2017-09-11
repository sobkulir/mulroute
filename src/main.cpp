#include "multi_traceroute.h"
#include "net/enums.h"

#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstdlib>
#include <unistd.h>

using std::vector;

constexpr AddressFamily DEF_AF_IN_UNKNOWN = AddressFamily::Inet;
constexpr int DEF_PROBES = 3;
constexpr int DEF_SENDWAIT = 10;
constexpr int DEF_WAITTIME = 500;
constexpr int DEF_START_TTL = 1;
constexpr int DEF_MAX_TTL = 30;
constexpr bool DEF_MAP_IP_TO_HOST = true;


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
        std::cout << "traceroute to " << dest[d].dest_str << " (" << dest[d].address.get_ip_str()
                  << "), " << options.max_ttl << " hops max\n";
        bool dest_reached = false;

        for (size_t ttl = 0; ttl + options.start_ttl <= last_arrived[d]; ++ttl) {
            std::cout << std::setw(2) << ttl + options.start_ttl;

            std::string last_ip = "";

            for (size_t p = 0; p < probes_info[d][ttl].size(); ++p) {
                const ProbeInfo &probe = probes_info[d][ttl][p];

                if (!probe.did_arrive) {
                    std::cout << "  *";
                    continue;
                }

                std::string ip = probe.offender.get_ip_str();
                int rtt = std::chrono::duration_cast<std::chrono::microseconds>(probe.recv_time - probe.send_time).count();

                if (ip != last_ip) {
                    if (p != 0) {
                        std::cout << "\n  ";
                    }

                    if (options.map_ip_to_host) {
                        std::cout << "  " << probe.offender.get_hostname() << " (" << ip << ")";
                    } else {
                        std::cout << "  " << ip;
                    }
                }

                std::cout << "  " << std::fixed << std::setprecision(3) << static_cast<double>(rtt) / 1000 << " ms";

                switch (probe.icmp_status) {
                    case IcmpRespStatus::HostUnreachable:
                        std::cout << "  !H";
                        dest_reached = true;
                        break;

                    case IcmpRespStatus::NetworkUnreachable:
                        std::cout << "  !N";
                        dest_reached = true;
                        break;

                    case IcmpRespStatus::ProtocolUnreachable:
                        std::cout << "  !P";
                        dest_reached = true;
                        break;

                    case IcmpRespStatus::AdminProhibited:
                        std::cout << "  !X";
                        dest_reached = true;
                        break;
                    case IcmpRespStatus::EchoReply:
                        dest_reached = true;
                        break;

                    default: break;
                }

                last_ip = ip;
            }

            std::cout << std::endl;
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
                std::cout << " .  * * *\n";
            }

            std::cout << std::setw(2) << options.max_ttl << "  * * *\n";
        }

        // Don't print newline after last destination
        if (d + 1 < dest.size()) {
            std::cout << std::endl;
        }
    }
}

TraceOptions get_args(int argc, char *const argv[], vector<std::string> &to_trace) {
    // Defaults
    TraceOptions options = {};

    options.af_if_unknown   = DEF_AF_IN_UNKNOWN;
    options.probes          = DEF_PROBES;
    options.sendwait        = DEF_SENDWAIT;
    options.waittime        = DEF_WAITTIME;
    options.start_ttl       = DEF_START_TTL;
    options.max_ttl         = DEF_MAX_TTL;
    options.map_ip_to_host  = DEF_MAP_IP_TO_HOST;

    std::string input_file;

    int opt;
    opterr = 0;
    while ((opt = getopt(argc, argv, "46f:m:np:z:w:")) != -1) {
        switch (opt) {
            case '4':
                options.af_if_unknown = AddressFamily::Inet;
                break;
            case '6':
                options.af_if_unknown = AddressFamily::Inet6;
                break;
            case 'f':
                options.start_ttl = std::stoi(optarg);
                break;
            case 'm':
                options.max_ttl = std::stoi(optarg);
                break;
            case 'n':
                options.map_ip_to_host = false;
                break;
            case 'p':
                options.probes = std::stoi(optarg);
                break;
            case 'z':
                options.sendwait = std::stoi(optarg);
                break;
            case 'w':
                options.waittime = std::stoi(optarg);
            case '?':
                std::cerr << "Usage: " << argv[0] << " [46nh] [-f start_ttl] [-m max_ttl] [-p nprobes]\n"
                    "          [-z sendwait] [-w waittime] [host...]\n\n"
                    "For more info use \"" << argv[0] << " -h\"\n";
                exit(EXIT_FAILURE);
            default:
                abort();
        }
    }

    to_trace.clear();

    if (optind < argc) {
        for (int i = optind; i < argc; ++i) {
            to_trace.push_back(argv[i]);
        }
    } else {
        std::string host;
        while (std::cin >> host) {
            to_trace.push_back(host);
        }
    }

    return options;
}

int main(int argc, char *const argv[]) {
    vector<std::string> to_trace;

    TraceOptions options = get_args(argc, argv, to_trace);

    TraceResult res;
    res = multi_traceroute(to_trace, options);

    print_routes(res.probes_info_ip4, res.dest_ip4, options);
    print_routes(res.probes_info_ip6, res.dest_ip6, options);

    exit(EXIT_SUCCESS);
}