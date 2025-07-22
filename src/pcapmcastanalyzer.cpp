// analyzer for multicast stream data in pcaps
// by kikman@gmx.de 
// based on the heavily stripped work of Erik Rigtorp <erik@rigtorp.se>, https://github.com/rigtorp/udpreplay/
// SPDX-License-Identifier: MIT

// stream = multicast address:port with a sequence number and optionally a senderid on fixed positions
// this tool checks if the sequence numbers are increasing (per senderid) and reports any mismatches

#include <cstring>
#include <iostream>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <stdio.h>
#include <map>
#include <set>
#include <vector>

typedef struct 
{
  uint16_t seqno_pos;
  uint16_t seqno_len;
  bool seqno_needs_bswap;
  uint16_t senderid_pos;
  uint16_t senderid_len;
  bool senderid_needs_bswap;
} streamtype_t;

std::map<std::string, std::map<uint16_t, streamtype_t>> streamtypes;
std::map<std::string, std::map<uint16_t, std::map<uint64_t, uint64_t>>> seqNo;
std::set<std::string> mentioned;

/* GRE header */
typedef struct 
{
  uint16_t gre_flags;		/* flags */
  uint16_t gre_protocol;	/* protocol */
} gre;


uint64_t get_value(uint8_t *buffer, int pos, int len, bool needs_bswap)
{
    uint64_t value = 0;
    if (len == 0) {
        return value; // Return 0 for length 0
    } else if (len == 1) {
        value = buffer[pos];
    } else if (len == 2) {
        value = *reinterpret_cast<const uint16_t *>(&buffer[pos]);
        if (needs_bswap) {
            value = __builtin_bswap16(value);
        }
    } else if (len == 4) {
        value = *reinterpret_cast<const uint32_t *>(&buffer[pos]);
        if (needs_bswap) {
            value = __builtin_bswap32(value);
        }
    } else if (len == 8) {
        value = *reinterpret_cast<const uint64_t *>(&buffer[pos]);
        if (needs_bswap) {
            value = __builtin_bswap64(value);
        }
    } else {
        std::cerr << "Invalid length for get_value: " << len << std::endl;
        return 0; // or handle error appropriately
    }
    return value;
}


int main(int argc, char *argv[]) {
  bool debug = false;
  std::string mcconfigfile;

  int opt;
  while ((opt = getopt(argc, argv, "dx:")) != -1) {
    switch (opt) {
    case 'd':
      debug = true;
      break;
    case 'x':
      mcconfigfile = optarg;
      if (mcconfigfile.empty()) {
        std::cerr << "<streamsdef file> must be provided" << std::endl;
        return 1;
      }
      break;
    default:
      goto usage;
    }
  }
  if (optind >= argc) {
  usage:
    std::cerr
        << "pcapstreamanalyzer 0.1\n"
           "usage: pcapstreamanalyzer [-d] [-x <streamsdef file>] pcap\n"
           "\n"
           "  -d          debug\n"
           "  -x          multicast streams definition file\n"

        << std::endl;
    return 1;
  }

  /* read mcconfigfile */
  if (!mcconfigfile.empty()) {
    FILE *fp = fopen(mcconfigfile.c_str(), "r");
    if (fp == nullptr) {
      std::cerr << "fopen: " << strerror(errno) << std::endl;
      return 1;
    }
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
      streamtype_t st;
      // Skip empty lines and comments
      if (line[0] == '\n' || line[0] == '#')
        continue;
      char *addr = strtok(line, ",");
      char *port = strtok(nullptr, ",");
      char *name = strtok(nullptr, ",");
      st.seqno_pos = atoi(strtok(nullptr, ","));
      st.seqno_len = atoi(strtok(nullptr, ","));
      st.seqno_needs_bswap = atoi(strtok(nullptr, ","));
      st.senderid_pos = atoi(strtok(nullptr, ","));
      st.senderid_len = atoi(strtok(nullptr, ","));
      st.senderid_needs_bswap = atoi(strtok(nullptr, ","));
      
      if (addr && port && name) {
        streamtypes[addr][atoi(port)] = st;
      }
      if ( debug )
      {
        printf("Read stream type: %s:%s, name: %s, senderid_pos: %d, senderid_len: %d, senderid_needs_bswap: %d, seqno_pos: %d, seqno_len: %d, seqno_needs_bswap: %d\n",
               addr, port, name, st.senderid_pos, st.senderid_len,
               st.senderid_needs_bswap, st.seqno_pos, st.seqno_len,
               st.seqno_needs_bswap);
      }
    }
    fclose(fp);
  }

  if (debug) {
    if (!mcconfigfile.empty()) {
      printf("Using multicast configuration file: %s\n", mcconfigfile.c_str());
    } else {
      printf("No multicast configuration file provided.\n");
    }
  }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline_with_tstamp_precision(
        argv[optind], PCAP_TSTAMP_PRECISION_NANO, errbuf);

    if (handle == nullptr) {
      std::cerr << "pcap_open: " << errbuf << std::endl;
      return 1;
    }

    pcap_pkthdr header;
    const u_char *p;
    while ((p = pcap_next(handle, &header))) {
      auto eth = reinterpret_cast<const ether_header *>(p);
      if (debug) {
        printf("\nEthernet packet with ether_type: %04x\n", ntohs(eth->ether_type));
      }

      if (header.len != header.caplen) {
        if ( debug )
        {
          printf("Warning: packet length mismatch: %u != %u\n", header.len,
                 header.caplen);
        }
        continue;
      }

      // jump over and ignore vlan tags
      while (ntohs(eth->ether_type) == ETHERTYPE_VLAN) {
        p += 4;
        eth = reinterpret_cast<const ether_header *>(p);
      }
      if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        if ( debug ) {
          printf("Ignoring non-IP packet with ether_type: %04x\n",ntohs(eth->ether_type));
        }
        continue;
      }
      auto ip = reinterpret_cast<const struct ip *>(p + sizeof(ether_header));
      if (ip->ip_v != 4) {
        if ( debug ) {
          printf("Ignoring non-IPv4 packet with version: %d\n", ip->ip_v);
        }
        continue;
      }
      if ( ip->ip_p != IPPROTO_UDP && ip->ip_p != IPPROTO_GRE ) {
        if ( debug ) {
          printf("Ignoring non-UDP/GRE packet with protocol: %d\n", ip->ip_p);
        }
        continue;
      }

      int msgoffset = sizeof(ether_header) + ip->ip_hl * 4;

      if ( ip->ip_p == IPPROTO_GRE ) {
        // If GRE mode, we need to handle the GRE header
        auto grehdr = reinterpret_cast<const gre *>(p + msgoffset);
        msgoffset += sizeof(gre);

        if ( debug ) {
          printf("GRE packet with flags: %04x, protocol: %04x\n",
                 ntohs(grehdr->gre_flags), ntohs(grehdr->gre_protocol));
        }

        // if checksum, then add 4 bytes to the offset
        if (grehdr->gre_flags & 0x0010) { // Check for checksum flag
          if (debug) {
            printf("-> GRE packet with checksum flag set: %04x\n",
                   ntohs(grehdr->gre_flags));
          }
          msgoffset += 4;
        }

        // if key, then add 4 bytes to the offset
        if (grehdr->gre_flags & 0x0020) { // Check for key flag
          if (debug) {
            printf("-> GRE packet with key flag set: %04x\n",
                   ntohs(grehdr->gre_flags));
          } 
          msgoffset += 4;
        }

        // if sequence, then add 4 bytes to the offset
        if (grehdr->gre_flags & 0x0040) { // Check for sequence flag
          if (debug) {
            printf("-> GRE packet with sequence flag set: %04x\n",  
                   ntohs(grehdr->gre_flags));            
          }
          msgoffset += 4;
        }

        ip = reinterpret_cast<const struct ip *>(p + msgoffset);
        msgoffset += ip->ip_hl * 4; // Update offset to include IP header

      }

      auto udp = reinterpret_cast<const udphdr *>(p + msgoffset);
      msgoffset += sizeof(udphdr);  // Update offset to include UDP header

#ifdef __GLIBC__
      ssize_t len = ntohs(udp->len) - 8;
#else
      ssize_t len = ntohs(udp->uh_ulen) - 8;
#endif
      if ( debug ) {
        printf("Packet %s:%u, len: %ld\n",
               inet_ntoa(ip->ip_dst), ntohs(udp->dest), len);
      }

      // now analyze the packet, we need to know the stream type
      // destination address:destination port, delta-time, packet length
      char *mcaddr = inet_ntoa(ip->ip_dst);
      uint16_t mcport = ntohs(udp->dest);
      streamtype_t type;

      if (streamtypes.find(mcaddr) != streamtypes.end() &&
          streamtypes[mcaddr].find(mcport) != streamtypes[mcaddr].end()) {
        type = streamtypes[mcaddr][mcport];
        if ( debug ) {
          printf("-> Found stream type for %s:%u: senderid_pos: %d, senderid_len: %d, senderid_needs_bswap: %d, seqno_pos: %d, seqno_len: %d, seqno_needs_bswap: %d\n",
                 mcaddr, mcport, type.senderid_pos, type.senderid_len,
                 type.senderid_needs_bswap, type.seqno_pos, type.seqno_len,
                 type.seqno_needs_bswap);
        }
      } else {
        // If not found, print a debug warning if debug
        if (debug) {
          std::string mcg = mcaddr;
          mcg += ":";
          mcg += std::to_string(mcport);
          if (mentioned.find(mcg) == mentioned.end()) {
            mentioned.insert(mcg);
            printf("-> Warning: %s:%u not found in streamtype map, ignoring\n", mcaddr, mcport);
          }
        }
        continue;
      }

      /* get senderConpID and sequence number depending on the type to be able to check the seqno */
      uint64_t senderid = get_value((uint8_t *)p + msgoffset, type.senderid_pos, type.senderid_len, type.senderid_needs_bswap);
      uint64_t seq = get_value((uint8_t *)p + msgoffset, type.seqno_pos, type.seqno_len, type.seqno_needs_bswap);

      if (debug) {
        printf("-> senderid: %lu, seq: %lu\n", senderid, seq);
      }

      if (seqNo.find(mcaddr) == seqNo.end()) {
        // Initialize the map for this multicast address
        seqNo[mcaddr] = std::map<uint16_t, std::map<uint64_t, uint64_t>>();
      }
      if (seqNo[mcaddr].find(mcport) == seqNo[mcaddr].end()) {
        // Initialize the map for this multicast port
        seqNo[mcaddr][mcport] = std::map<uint64_t, uint64_t>();
      }

      if (seqNo[mcaddr][mcport].find(senderid) == seqNo[mcaddr][mcport].end()) {
        // Initialize the sequence number for this senderid
        if (debug) {
          printf("-> Initializing sequence number for %s:%u senderid: %lu\n",
                 mcaddr, mcport, senderid);
        }
        seqNo[mcaddr][mcport][senderid] = seq;
      } else {
        // check if the sequence number is increasing
        if (seqNo[mcaddr][mcport][senderid]+1 != seq)
        {
          printf("-> Sequence number mismatch for %s:%u senderid: %lu, expected: %lu, got: %lu\n",
                 mcaddr, mcport, 
                 senderid,
                 seqNo[mcaddr][mcport][senderid]+1, seq);
        }
        else
        {
          if (debug) {
            printf("-> OK - Sequence number for %s:%u senderid: %lu is increasing by one: %lu -> %lu\n",
                   mcaddr, mcport, senderid,
                   seqNo[mcaddr][mcport][senderid], seq);
          }
        }
        // Update the sequence number
        seqNo[mcaddr][mcport][senderid] = seq;
      }

    }
    pcap_close(handle);

  return 0;
}
