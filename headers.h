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

#ifndef CLERK_HEADERS_H_
#define CLERK_HEADERS_H_

#include <netinet/if_ether.h>  // ethhdr
#define __FAVOR_BSD
#include <netinet/tcp.h>  // tcphdr
#undef __FAVOR_BSD
#include <netinet/icmp6.h>    // icmp6_hdr
#include <netinet/ip.h>       // iphdr
#include <netinet/ip6.h>      // ip6_hdr
#include <netinet/ip_icmp.h>  // icmphdr
#include <netinet/udp.h>      // udphdr

#include "util.h"

namespace clerk {

struct Headers {
  Headers();

  void Reset();

  // Parse the given packet data, setting the found header pointers in this
  // struct.  Note that initially we expect to find an ethernet header first,
  // other link types are not yet supported (though they could be later on).
  void Parse(StringPiece p);

  // These pointers are reset to NULL on every call to Parse, then those
  // associated with the packet are set.

  // Layer 2
  const struct ethhdr* eth;

  // Layer 3
  const struct iphdr* ip4;
  const struct ip6_hdr* ip6;

  // Layer 4
  const struct tcphdr* tcp;
  const struct udphdr* udp;
  const struct icmphdr* icmp4;
  const struct icmp6_hdr* icmp6;

  // Other metadata
  const struct ip6_frag* ip6frag;
};

}  // namespace clerk

#endif  // CLERK_HEADERS_H_
