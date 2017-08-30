//
// Roman Sobkuliak 27.8.2017
//

#include "multi_traceroute.h"
#include "net/Address.h"
#include "net/GaiException.h"
#include "net/utility.h"
#include "net/Socket.h"
#include "net/IcmpHeader.h"

#include <vector>
#include <string>
#include <iostream>
#include <tuple>
#include <memory>
#include <random>
#include <chrono>
#include <thread>

constexpr int ICMP_SEQ_ID_MAX = (1 << 16) - 1;
constexpr int TTL_DONE_INIT = 100;

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

std::tuple<std::vector<DestInfo>, std::vector<DestInfo>, std::vector<DestInfo>>
resolve_addresses(const std::vector<std::string> &dest_str_vec, AddressFamily af_if_unknown) {
    std::vector<DestInfo> dest_ip4, dest_ip6, dest_error;

    for (int i = 0; i < dest_str_vec.size(); ++i) {
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

void send_probes(AddressFamily af,
                 const std::vector<DestInfo> &dest,
                 const std::vector<int> &ttl_done,
                 int id_offset,
                 int seq_offset,
                 TraceOptions options)
{
    Socket sock = Socket(af, SocketType::Datagram, (af == AddressFamily::Inet) ? Protocol::ICMP : Protocol::ICMPv6);

    // Initialize ICMP echo request packet
    std::vector<char> payload = {'a', 'b', 'r', 'a', 'h', 'a', 'm'};
    std::shared_ptr<IcmpHeader> icmp_hdr;

    if (af == AddressFamily::Inet) {
        icmp_hdr = std::make_shared<Icmp4Header>(id_offset, seq_offset, payload, payload.size());
    } else {
        icmp_hdr = std::make_shared<Icmp6Header>(id_offset, seq_offset, payload, payload.size());
    }

    for (int ttl = 1; ttl <= options.max_ttl; ++ttl) {
        sock.set_ttl(ttl);

        for (int p = 0; p < options.probes; ++p) {
            icmp_hdr->set_seq(seq_offset + ttl * options.probes + p);

            for (int i = 0; i < dest.size(); ++i) {
                // Destination is already reached
                if (ttl_done[i] < ttl) {
                    continue;
                }

                icmp_hdr->set_id(id_offset + i);
                icmp_hdr->prep_to_send();

                sock.send(icmp_hdr->get_packet_ptr(), icmp_hdr->get_length(), dest[i].address);
                //std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }
        }
    }
}


std::vector<std::vector<Probe>> multi_traceroute(std::vector<std::string> dest_str_vec, TraceOptions options) {
    std::vector<DestInfo> dest_ip4, dest_ip6, dest_error;
    std::tie(dest_ip4, dest_ip6, dest_error) = resolve_addresses(dest_str_vec, options.af_if_unknown);

    std::vector<int> ttl_done_ip4(dest_ip4.size(), TTL_DONE_INIT),
                     ttl_done_ip6(dest_ip6.size(), TTL_DONE_INIT);

    std::random_device r;
    std::default_random_engine e1(r());
    std::uniform_int_distribution<int> icmp4_dist(0, ICMP_SEQ_ID_MAX - dest_ip4.size() * options.probes),
                                       icmp6_dist(0, ICMP_SEQ_ID_MAX - dest_ip6.size() * options.probes);

    int icmp4_id_offset = icmp4_dist(e1),
        icmp4_seq_offset = icmp4_dist(e1),
        icmp6_id_offset = icmp6_dist(e1),
        icmp6_seq_offset = icmp6_dist(e1);


    send_probes(AddressFamily::Inet, dest_ip4, ttl_done_ip4, icmp4_id_offset, icmp4_seq_offset, options);

    // kill receiving thread

    // the same for IPv6

    // compute RTTs for probes
    // resolve hostnames

    // happily return, YAY
    return std::vector<std::vector<Probe>>();
}