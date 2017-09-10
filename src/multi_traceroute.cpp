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

// SEQ and ID are 16bit unsigned numbers
constexpr int ICMP_SEQ_ID_MAX = (1 << 16) - 1;

constexpr int DEF_TTL_DONE = 100;
constexpr int RECV_TIMEOUT_SEC = 0;
constexpr int RECV_TIMEOUT_USEC = 200000;
constexpr int RECV_BUF_SIZE = 1500;
constexpr int MIN_IP4_HDR_LEN = 20;
constexpr int MIN_IP6_HDR_LEN = 40;
constexpr int ICMP_HDR_LEN = 8;

using std::vector;

inline int get_ip_hdr_len(AddressFamily af, char *ip_hdr) {
    if (af == AddressFamily::Inet) {
        struct ip *ip4_p = (struct ip *) ip_hdr;
        return ip4_p->ip_hl << 2;
    } else {
        // IPv6 headers are fixed length (40 bytes)
        return MIN_IP6_HDR_LEN;
    }
}

inline int min_ip_hdr_len(AddressFamily af) {
    if (af == AddressFamily::Inet) {
        return MIN_IP4_HDR_LEN;
    } else {
        return MIN_IP6_HDR_LEN;
    }
}


/*
 * Every ICMP Echo Request packet has ID and SEQ_NUMBER.
 * We use these numbers to match our EchoRequests to replies.
 * First a random id_offset and seq_offset is computed.
 *    ID holds the information about destination (index in vector of destinations)
 *    and is computed as:
 *      id_offset + dest_index
 *
 *    SEQ holds information about ttl and probe number. We compute it as
 *      seq_offset + (ttl - 1) * max_probes + probes
 *      (considering ttl starts with 1)
 */

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

/*
 * Function sends options.max_probes for every ttl (up to options.max_ttl)
 * to every destination in dest vector.
 *
 * dest         - a vector containing destinations for sending probes
 * ttl_done     - a vector where k-th element is the smallest ttl of packet which reached k-th
 *                destination from dest vector
 * probes_info  - information about every probe sent
 */
void send_probes(AddressFamily af,
                 const vector<DestInfo> &dest,
                 const vector<int> &ttl_done,
                 vector<vector<vector<ProbeInfo>>> &probes_info,
                 int id_offset,
                 int seq_offset,
                 TraceOptions options)
{
    Socket sock = Socket(af, SocketType::Raw, (af == AddressFamily::Inet) ? Protocol::ICMP : Protocol::ICMPv6);

    // Initialize ICMP echo request packet with message 'abraham'
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

/*
 * Function is receiving all ICMP packets of given address family. If the packet is
 * our probe (based on ID and SEQ), information about it are updated in probes_info vector.
 *
 * Since this function will run simultaneously with send_probes, we need to know when to stop it.
 * Variable all_sent is used exactly for this - when all probes are sent, all_sent variable is set to
 * true and we stop receiving roughly after options.timeout_len miliseconds.
 *
 * ttl_done     - a vector where k-th element is the smallest ttl of packet which reached k-th
 *                destination from dest vector (used in send_probes).
 */
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
    std::chrono::steady_clock::time_point all_sent_time;

    Address from;
    char recv_buf[RECV_BUF_SIZE];

    while (true) {

        if (all_sent) {
            /*
             * All probes have been sent, we start timeout of options.timeout_len miliseconds and then
             * terminate.
             */
            if (timeout_started) {
                std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - all_sent_time).count() > options.timeout_len) {
                    break;
                }
            } else {
                all_sent_time = std::chrono::steady_clock::now();
                timeout_started = true;
            }
        }

        /*
         * Passively wait at most RECV_TIMEOUT_SEC seconds + RECV_TIMEOUT_USEC microseconds for
         * socket to be ready for reading.
         */
        if (!sock.wait_for_recv(RECV_TIMEOUT_SEC, RECV_TIMEOUT_USEC)) {
            continue;
        }

        auto recv_time = std::chrono::steady_clock::now();

        int n_bytes = sock.recv(recv_buf, RECV_BUF_SIZE, from);
        for (int i = 0; i < n_bytes; ++i) {
            printf("%02X ", ((unsigned char *) recv_buf)[i]);
        }
        std::cout << std::endl;

        /*
         *                                 ICMPv4 ERROR responses
         *
         *   ***************** ***************** ***************** ***************************
         *   *  IPv4 header  * *  ICMPv4 error * *  IPv4 header  * *  original ICMPv4 header *
         *   *   ~20 bytes   * *    8 bytes    * *   ~20 bytes   * *          8 bytes        *
         *   ***************** ***************** ***************** ***************************
         *
         *  Echo replies contain IPv4 header and ICMPv4 Echo reply message
         *
         *                                  ICMPv6 ERROR responses
         *
         *             ***************** ***************** ***************************
         *             *  ICMPv6 error * *  IPv6 header  * *  original ICMPv6 header *
         *             *    8 bytes    * *    40 bytes   * *          8 bytes        *
         *             ***************** ***************** ***************************
         *
         *  Echo replies contain only ICMPv6 Echo reply message
         */

        std::shared_ptr<IcmpHeader> icmp_hdr;
        int ip_hdr_len1, ip_hdr_len2;

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

        // Validate ID and SEQ
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

void send_and_recv(AddressFamily af,
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

        /*
         * If sending fails, we have to set all_sent to true so that receiving terminates
         */
        all_sent = true;
        t1.join();
        exit(EXIT_FAILURE);
    }

    all_sent = true;
    t1.join();
}

void multi_traceroute(vector<std::string> dest_str_vec, TraceOptions options, TraceResult res) {

    // Resolving users input addresses into Address structures
    for (std::string ip_or_hostname : dest_str_vec) {
        try {
            Address dest_address = str_to_address(ip_or_hostname, options.af_if_unknown);

            if (dest_address.get_family() == AddressFamily::Inet) {
                res.dest_ip4.push_back(DestInfo(dest_address, ip_or_hostname, true));
            } else {
                res.dest_ip6.push_back(DestInfo(dest_address, ip_or_hostname, true));
            }

        } catch (const GaiException& e) {
            std::cerr << "Skipping \"" << ip_or_hostname << "\", an exception was caught: "
                      << "\n\tError code: " << e.code() << " " << e.what() << std::endl;

            res.dest_error.push_back(DestInfo(Address(), ip_or_hostname, false));
        }
    }


    vector<int> ttl_done,
                ttl_done_ip4(res.dest_ip4.size(), DEF_TTL_DONE),
                ttl_done_ip6(res.dest_ip6.size(), DEF_TTL_DONE);

    std::random_device r;
    std::default_random_engine e1(r());
    std::uniform_int_distribution<int> icmp4_dist(0, ICMP_SEQ_ID_MAX - res.dest_ip4.size() * options.probes),
                                       icmp6_dist(0, ICMP_SEQ_ID_MAX - res.dest_ip6.size() * options.probes);

    int icmp4_id_offset = icmp4_dist(e1),
        icmp4_seq_offset = icmp4_dist(e1),
        icmp6_id_offset = icmp6_dist(e1),
        icmp6_seq_offset = icmp6_dist(e1);

    if (res.dest_ip4.size() > 0) {
        send_and_recv(AddressFamily::Inet,
              res.dest_ip4,
              ttl_done_ip4,
              res.probes_info_ip4,
              icmp4_id_offset,
              icmp4_seq_offset,
              options);
    }
    if (res.dest_ip6.size() > 0) {
        send_and_recv(AddressFamily::Inet6,
              res.dest_ip6,
              ttl_done_ip6,
              res.probes_info_ip6,
              icmp6_id_offset,
              icmp6_seq_offset,
              options);
    }

    // resolve hostnames

}