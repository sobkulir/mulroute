//
// Roman Sobkuliak 27.8.2017
//

#include "multi_traceroute.h"
#include "net/Address.h"
#include "net/GaiException.h"
#include "net/utility.h"
#include "net/Socket.h"
#include "net/IcmpHeader.h"

#include <netinet/ip.h>
#include <vector>
#include <string>
#include <iostream>
#include <tuple>
#include <memory>
#include <random>
#include <chrono>
#include <thread>
#include <exception>
#include <cstdlib>

#include <cstdio>

constexpr int ICMP_SEQ_ID_MAX = (1 << 16) - 1;
constexpr int DEF_TTL_DONE = 100;
constexpr int TIME_FOR_RECV = 1;
constexpr int RECV_BUF_SIZE = 1500;
constexpr int MIN_IP4_HDR_LEN = 20;
constexpr int MIN_IP6_HDR_LEN = 40;
constexpr int ICMP_HDR_LEN = 8;

typedef std::chrono::steady_clock::time_point time_point;
using std::vector;

class DestInfo {
public:
    DestInfo() {
        address = Address();
    }
    DestInfo(Address address, std::string dest_str, bool valid) :
        address(address), dest_str(dest_str), address_valid(valid) { }
    Address address;
    std::string dest_str;
    bool address_valid;
};


class ProbeInfo {
public:
    ProbeInfo() { };
    Address offender;
    IcmpRespStatus icmp_status;
    time_point send_time, recv_time;
    bool did_arrive = false;
};

std::tuple<vector<DestInfo>, vector<DestInfo>, vector<DestInfo>>
resolve_addresses(const vector<std::string> &dest_str_vec, AddressFamily af_if_unknown) {
    vector<DestInfo> dest_ip4, dest_ip6, dest_error;

    for (size_t i = 0; i < dest_str_vec.size(); ++i) {
        AddressFamily af = ip_version(dest_str_vec[i]);
        if (af == AddressFamily::Unspec) {
            af = af_if_unknown;
        }

        try {
            Address dest_address = str_to_address(dest_str_vec[i], af);

            if (dest_address.get_family() == AddressFamily::Inet) {
                dest_ip4.push_back(DestInfo(dest_address, dest_str_vec[i], true));
            } else {
                dest_ip6.push_back(DestInfo(dest_address, dest_str_vec[i], true));
            }
        } catch (const GaiException& e) {
            std::cerr << "Skipping \"" << dest_str_vec[i] << "\", an exception was caught: "
                      << "\n\tError code: " << e.code() << " " << e.what() << std::endl;
            dest_error.push_back(DestInfo(Address(), dest_str_vec[i], false));
        }
    }

    return std::make_tuple(dest_ip4, dest_ip6, dest_error);
}

inline int get_ip_hdr_len(AddressFamily af, char *ip_hdr) {
    if (af == AddressFamily::Inet) {
        struct ip *ip4_p = (struct ip *) ip_hdr;
        return ip4_p->ip_hl << 2;
    } else {
        return MIN_IP6_HDR_LEN;
    }
}

inline int dest_to_id(int dest_ind, int id_offset) {
    return id_offset + dest_ind;
}

inline int id_to_dest(int id, int id_offset) {
    return id - id_offset;
}

inline int probe_to_seq(int ttl, int probes, int p, int seq_offset) {
    return seq_offset + (ttl - 1) * probes + p;
}

inline int seq_to_ttl(int seq, int probes, int seq_offset) {
    return (seq - seq_offset) / probes + 1;
}

inline int seq_to_probe(int seq, int probes, int seq_offset) {
    return (seq - seq_offset) % probes;
}

inline int min_ip_hdr_len(AddressFamily af) {
    if (af == AddressFamily::Inet) {
        return MIN_IP4_HDR_LEN;
    } else {
        return MIN_IP6_HDR_LEN;
    }
}

void send_probes(AddressFamily af,
            const vector<DestInfo> &dest,
            const vector<int> &ttl_done,
            vector<vector<vector<ProbeInfo>>> &probes_info,
            int id_offset,
            int seq_offset,
            TraceOptions options)
{
    Socket sock = Socket(af, SocketType::Raw, (af == AddressFamily::Inet) ? Protocol::ICMP : Protocol::ICMPv6);

    // Initialize ICMP echo request packet
    vector<char> payload = {'a', 'b', 'r', 'a', 'h', 'a', 'm'};
    std::shared_ptr<IcmpHeader> icmp_hdr;

    if (af == AddressFamily::Inet) {
        icmp_hdr = std::make_shared<Icmp4Header>(id_offset, seq_offset, payload, payload.size());
    } else {
        icmp_hdr = std::make_shared<Icmp6Header>(id_offset, seq_offset, payload, payload.size());
    }

    for (int ttl = 1; ttl <= options.max_ttl; ++ttl) {
        sock.set_ttl(ttl);

        for (int p = 0; p < options.probes; ++p) {
            icmp_hdr->set_seq(probe_to_seq(ttl, options.probes, p, seq_offset));

            for (size_t i = 0; i < dest.size(); ++i) {
                // Destination is already reached
                if (ttl_done[i] < ttl) {
                    continue;
                }

                icmp_hdr->set_id(dest_to_id(i, id_offset));
                icmp_hdr->prep_to_send();

                probes_info[i][ttl - 1][p].send_time = std::chrono::steady_clock::now();

                sock.send(icmp_hdr->get_packet_ptr(), icmp_hdr->get_length(), dest[i].address);
                std::this_thread::sleep_for(std::chrono::milliseconds(options.break_len));
            }
        }
    }
}

void recv_probes(AddressFamily af,
                 vector<int> &ttl_done,
                 bool &all_sent,
                 vector<vector<vector<ProbeInfo>>> &probes_info,
                 int id_offset,
                 int seq_offset,
                 TraceOptions options)
{
    Socket sock = Socket(af, SocketType::Raw, (af == AddressFamily::Inet) ? Protocol::ICMP : Protocol::ICMPv6);
    bool timeout_started = false;
    time_point all_sent_time;
    Address from;
    char recv_buf[RECV_BUF_SIZE];

    while (true) {
        if (all_sent) {
            if (!timeout_started) {
                all_sent_time = std::chrono::steady_clock::now();
                timeout_started = true;
            } else {
                time_point now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - all_sent_time).count() > options.timeout_len) {
                    break;
                }
            }
        }

        // Waiting timed out, no packet to read
        if (!sock.wait_for_recv(TIME_FOR_RECV)) {
            continue;
        }

        auto recv_time = std::chrono::steady_clock::now();

        int n_bytes = sock.recv(recv_buf, RECV_BUF_SIZE, from);
        for (int i = 0; i < n_bytes; ++i) {
            printf("%02X ", ((unsigned char *) recv_buf)[i]);
        }
        std::cout << std::endl;

        std::shared_ptr<IcmpHeader> icmp_hdr;
        int ip_hdr_len1, ip_hdr_len2;

        // IPv4 packets come with IP header, IPv6 packets don't
        if (af == AddressFamily::Inet) {

            // Is enough bytes received for EchoReply
            if (n_bytes < min_ip_hdr_len(af) + ICMP_HDR_LEN) {
                continue;
            }

            ip_hdr_len1 = get_ip_hdr_len(AddressFamily::Inet, recv_buf);
            icmp_hdr = std::make_shared<Icmp4Header>(recv_buf + ip_hdr_len1, n_bytes - ip_hdr_len1);
        } else {

            if (n_bytes < ICMP_HDR_LEN) {
                continue;
            }

            // No IPv6 header to process in case of IPv6
            ip_hdr_len1 = 0;
            icmp_hdr = std::make_shared<Icmp6Header>(recv_buf, n_bytes - ip_hdr_len1);
        }

        IcmpRespStatus icmp_status = icmp_hdr->get_resp_status();

        switch (icmp_status) {
            case IcmpRespStatus::Unknown:
                continue;
            case IcmpRespStatus::EchoReply: {
                break;
            }
            default: {
                // Is enough bytes received for error
                if (n_bytes < ip_hdr_len1 + ICMP_HDR_LEN + min_ip_hdr_len(af) + 8) {
                    continue;
                }

                ip_hdr_len2 = get_ip_hdr_len(af, recv_buf + ip_hdr_len1 + ICMP_HDR_LEN);

                if (af == AddressFamily::Inet) {
                    icmp_hdr = std::make_shared<Icmp4Header>(
                        recv_buf + ip_hdr_len1 + ICMP_HDR_LEN + ip_hdr_len2,
                        n_bytes - ip_hdr_len1 - ICMP_HDR_LEN - ip_hdr_len2);
                } else {
                    icmp_hdr = std::make_shared<Icmp6Header>(
                        recv_buf + ICMP_HDR_LEN + ip_hdr_len2,
                        n_bytes - ICMP_HDR_LEN - ip_hdr_len2);
                }
            }
        }

        int dest_ind = id_to_dest(icmp_hdr->get_id(), id_offset);
        int ttl = seq_to_ttl(icmp_hdr->get_seq(), options.probes, seq_offset);
        int probe_ind = seq_to_probe(icmp_hdr->get_seq(), options.probes, seq_offset);

        if (dest_ind < 0 || dest_ind >= static_cast<int>(ttl_done.size())
            || ttl < 1 || ttl > options.max_ttl
            || probe_ind < 0 || probe_ind > options.probes) {
            continue;
        }

        if (icmp_status != IcmpRespStatus::TimeExceeded) {
            // Received probe is useless, we reached destination with smaller ttl
            if (ttl_done[dest_ind] < ttl) {
                continue;
            } else {
                ttl_done[dest_ind] = ttl;
            }
        }

        ProbeInfo &probe_ref = probes_info[dest_ind][ttl - 1][probe_ind];
        probe_ref.offender = from;
        probe_ref.did_arrive = true;
        probe_ref.icmp_status = icmp_status;
        probe_ref.recv_time = recv_time;
    }

}

void trace(AddressFamily af,
           const vector<DestInfo> &dest,
           vector<int> &ttl_done,
           vector<vector<vector<ProbeInfo>>> &probes_info,
           int id_offset,
           int seq_offset,
           TraceOptions options)
{
    bool all_sent = false;
    probes_info.assign(dest.size(), vector<vector<ProbeInfo>>(options.max_ttl, vector<ProbeInfo>(options.probes, ProbeInfo())));

    std::thread t1(recv_probes,
                   af,
                   std::ref(ttl_done),
                   std::ref(all_sent),
                   std::ref(probes_info),
                   id_offset,
                   seq_offset,
                   options);

    try {
        send_probes(af, dest, ttl_done, probes_info, id_offset, seq_offset, options);
    } catch (const std::exception &e) {
        std::cerr << "Caught exception: " << e.what() << std::endl;
        all_sent = true;
        t1.join();
        exit(EXIT_FAILURE);
    }

    all_sent = true;
    t1.join();
}

vector<vector<Probe>> multi_traceroute(vector<std::string> dest_str_vec, TraceOptions options) {
    vector<DestInfo> dest, dest_ip4, dest_ip6, dest_error;
    std::tie(dest_ip4, dest_ip6, dest_error) = resolve_addresses(dest_str_vec, options.af_if_unknown);

    vector<int> ttl_done,
                ttl_done_ip4(dest_ip4.size(), DEF_TTL_DONE),
                ttl_done_ip6(dest_ip6.size(), DEF_TTL_DONE);

    std::random_device r;
    std::default_random_engine e1(r());
    std::uniform_int_distribution<int> icmp4_dist(0, ICMP_SEQ_ID_MAX - dest_ip4.size() * options.probes),
                                       icmp6_dist(0, ICMP_SEQ_ID_MAX - dest_ip6.size() * options.probes);

    int icmp4_id_offset = icmp4_dist(e1),
        icmp4_seq_offset = icmp4_dist(e1),
        icmp6_id_offset = icmp6_dist(e1),
        icmp6_seq_offset = icmp6_dist(e1);

    vector<vector<vector<ProbeInfo>>> probes_info, probes_info_ip4, probes_info_ip6;

    if (dest_ip4.size() > 0) {
        trace(AddressFamily::Inet, dest_ip4, ttl_done_ip4, probes_info_ip4, icmp4_id_offset, icmp4_seq_offset, options);
    }
    if (dest_ip6.size() > 0) {
        trace(AddressFamily::Inet6, dest_ip6, ttl_done_ip6, probes_info_ip6, icmp6_id_offset, icmp6_seq_offset, options);
    }

    // Merge results
    probes_info = probes_info_ip4;
    probes_info.insert(probes_info.end(), probes_info_ip6.begin(), probes_info_ip6.end());

    ttl_done = ttl_done_ip4;
    ttl_done.insert(ttl_done.end(), ttl_done_ip6.begin(), ttl_done_ip6.end());

    dest = dest_ip4;
    dest.insert(dest.end(), dest_ip6.begin(), dest_ip6.end());

    for (size_t i = 0; i < dest.size(); ++i) {
        std::cout << dest[i].dest_str << std::endl;
        if (!dest[i].address_valid) {
            std::cout << "\t" << "Errored" << std::endl;
            continue;
        }
        for (int ttl = 0; ttl < std::min(ttl_done[i], options.max_ttl); ++ttl) {
            std::cout << "\tTTL: " << ttl+1 << std::endl;
            for (int p = 0; p < options.probes; ++p) {
                std::cout << "\t\tProbe: " << p << std::endl;
                ProbeInfo &probe = probes_info[i][ttl][p];
                std::cout << "\t\t\tArrived: " << probe.did_arrive << std::endl;
            }
        }
    }
    // compute RTTs for probes
    // resolve hostnames

    // happily return, YAY
    return vector<vector<Probe>>();
}