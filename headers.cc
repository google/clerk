// Copyright 2016 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "headers.h"

#include <netinet/in.h>  // ntohs(), ntohl()
#include <string.h>

namespace clerk {

namespace {

// kTypeEthernet is NOT a valid ETH_P_ type.  We use it to signify that the next
// layer to decode is an ethernet header.
const uint16_t kTypeEthernet = 0;
const uint16_t kProtocolUnknown = 0;
const uint32_t kMPLSBottomOfStack = 1 << 8;

}  // namespace

Headers::Headers() { Reset(); }

void Headers::Reset() { memset(this, 0, sizeof(*this)); }

void Headers::Parse(StringPiece p) {
  Reset();
  const char* start = p.data();
  const char* limit = start + p.size();
  uint16_t type = kTypeEthernet;
  uint16_t protocol = kProtocolUnknown;

// We use a goto loop within this switch statement to strip all pre-IP-header
// layers off of the given packet.
pre_ip_encapsulation:
  switch (type) {
    case kTypeEthernet: {
      if (start + sizeof(struct ethhdr) > limit) {
        return;
      }
      eth = reinterpret_cast<const struct ethhdr*>(start);
      start += sizeof(struct ethhdr);
      type = ntohs(eth->h_proto);
      goto pre_ip_encapsulation;
    }
    case ETH_P_8021Q:
      FALLTHROUGH_INTENDED;
    case ETH_P_8021AD:
      FALLTHROUGH_INTENDED;
    case ETH_P_QINQ1:
      FALLTHROUGH_INTENDED;
    case ETH_P_QINQ2:
      FALLTHROUGH_INTENDED;
    case ETH_P_QINQ3: {
      if (start + 4 > limit) {
        return;
      }
      // AddVLAN(ntohs(*reinterpret_cast<const uint16_t*>(start)) & 0x0FFF,
      // packet_offset);
      type = ntohs(*reinterpret_cast<const uint16_t*>(start + 2));
      start += 4;
      goto pre_ip_encapsulation;
    }
    case ETH_P_MPLS_UC:
      FALLTHROUGH_INTENDED;
    case ETH_P_MPLS_MC: {
      uint32_t mpls_header = 0;
      do {
        // We check for 5 bytes, because we need to parse the first nibble after
        // the MPLS header to figure out the next layer type.
        if (start + 5 > limit) {
          return;
        }
        mpls_header = ntohl(*reinterpret_cast<const uint32_t*>(start));
        // AddMPLS(mpls_header >> 12, packet_offset);
        start += 4;
      } while (!(mpls_header & kMPLSBottomOfStack));
      // Use the first nibble after the last MPLS layer to determine the
      // underlying packet type.
      switch (start[0] >> 4) {
        case 0:  // RFC4385
          type = kTypeEthernet;
          start += 4;  // Skip over PW ethernet control word.
          break;
        case 4:
          type = ETH_P_IP;
          break;
        case 6:
          type = ETH_P_IPV6;
          break;
        default:
          return;
      }
      goto pre_ip_encapsulation;
    }

    // All of the above use the pre_ip_encapsulation loop.
    // All of the below do not.

    case ETH_P_IP: {
      if (start + sizeof(struct iphdr) > limit) {
        return;
      }
      ip4 = reinterpret_cast<const struct iphdr*>(start);
      size_t len = ip4->ihl;
      len *= 4;
      if (len < 20) return;
      protocol = ip4->protocol;
      start += len;
      break;
    }
    case ETH_P_IPV6: {
      if (start + sizeof(struct ip6_hdr) > limit) {
        return;
      }
      ip6 = reinterpret_cast<const struct ip6_hdr*>(start);
      protocol = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
      start += sizeof(struct ip6_hdr);

    // Here, we use another goto loop to strip off all IPv6 extensions.
    ip6_extensions:
      switch (protocol) {
        case IPPROTO_FRAGMENT: {
          if (start + sizeof(struct ip6_frag) > limit) {
            return;
          }
          ip6frag = reinterpret_cast<const struct ip6_frag*>(start);
          if (ntohs(ip6frag->ip6f_offlg) & 0xfff8) {
            // If we're not the first fragment, break out of the loop so we
            // can store the IPs we have but recognize in the protocol switch
            // later on that we don't know what this packet is.
            break;
          }
          // otherwise, fall through to treating this like any other
          // extension.
          FALLTHROUGH_INTENDED;
        }
#ifdef IPPROTO_MH
        case IPPROTO_MH:
          FALLTHROUGH_INTENDED;
#endif
        case IPPROTO_HOPOPTS:
          FALLTHROUGH_INTENDED;
        case IPPROTO_ROUTING:
          FALLTHROUGH_INTENDED;
        case IPPROTO_DSTOPTS: {
          if (start + sizeof(struct ip6_ext) > limit) {
            return;
          }
          auto ip6ext = reinterpret_cast<const struct ip6_ext*>(start);
          protocol = ip6ext->ip6e_nxt;
          start += (ip6ext->ip6e_len + 1) * 8;
          goto ip6_extensions;
        }
      }
      break;
    }
    default:
      return;
  }

#define LAYER_4_PROTOCOL(typ, name, strct)               \
  case typ: {                                            \
    if (start + sizeof(struct strct) > limit) {          \
      return;                                            \
    }                                                    \
    name = reinterpret_cast<const struct strct*>(start); \
    start += sizeof(struct strct);                       \
    break;                                               \
  }
  switch (protocol) {
    LAYER_4_PROTOCOL(IPPROTO_TCP, tcp, tcphdr)
    LAYER_4_PROTOCOL(IPPROTO_UDP, udp, udphdr)
    LAYER_4_PROTOCOL(IPPROTO_ICMP, icmp4, icmphdr)
    LAYER_4_PROTOCOL(IPPROTO_ICMPV6, icmp6, icmp6_hdr)
    default:
      return;
  }
#undef LAYER_4_PROTOCOL
}

}  // namespace clerk
