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

#ifndef CLERK_FLOW_H_
#define CLERK_FLOW_H_

#include <unordered_map>

#include <glog/logging.h>

namespace clerk {
namespace flow {

struct Key {
  Key();

  uint8_t src_ip[16];
  uint8_t dst_ip[16];
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t vlan;
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint8_t network;  // 0 = unknown, 4 = ipv4, 6 = ipv6
  uint8_t protocol;
  uint8_t tos;  // IPv4 TOS, IPv6 traffic class

  bool operator==(const Key& b) const;
  inline bool operator!=(const Key& b) const { return !operator==(b); }
  size_t hash() const;
  void set_src_ip4(uint32_t ip4);
  void set_dst_ip4(uint32_t ip4);
  void set_network(uint8_t net);
  uint32_t get_src_ip4() const;
  uint32_t get_dst_ip4() const;
  void set_src_ip6(const char* ip6);
  void set_dst_ip6(const char* ip6);
};

inline void Key::set_network(uint8_t net) {
  if (__builtin_expect((network == 6 && net == 4), false)) {
    // If we switch from v6 to v4, we need to clear the bits of the IPs.
    memset(src_ip, 0, sizeof(src_ip));
    memset(dst_ip, 0, sizeof(dst_ip));
  }
  network = net;
}
inline void Key::set_src_ip4(uint32_t ip4) {
  set_network(4);
  src_ip[12] = ip4 >> 24;
  src_ip[13] = ip4 >> 16;
  src_ip[14] = ip4 >> 8;
  src_ip[15] = ip4;
}
inline void Key::set_dst_ip4(uint32_t ip4) {
  set_network(4);
  dst_ip[12] = ip4 >> 24;
  dst_ip[13] = ip4 >> 16;
  dst_ip[14] = ip4 >> 8;
  dst_ip[15] = ip4;
}
#define LEFT_SHIFT_32(x, by) (((uint32_t)(x)) << (by))
inline uint32_t Key::get_src_ip4() const {
  CHECK_EQ(network, 4);
  return LEFT_SHIFT_32(src_ip[12], 24) |
         LEFT_SHIFT_32(src_ip[13], 16) |
         LEFT_SHIFT_32(src_ip[14], 8) |
         LEFT_SHIFT_32(src_ip[15], 0);
}
inline uint32_t Key::get_dst_ip4() const {
  CHECK_EQ(network, 4);
  return LEFT_SHIFT_32(dst_ip[12], 24) |
         LEFT_SHIFT_32(dst_ip[13], 16) |
         LEFT_SHIFT_32(dst_ip[14], 8) |
         LEFT_SHIFT_32(dst_ip[15], 0);
}
#undef LEFT_SHIFT_32
inline void Key::set_src_ip6(const char* ip6) {
  set_network(6);
  memcpy(src_ip, ip6, sizeof(src_ip));
}
inline void Key::set_dst_ip6(const char* ip6) {
  set_network(6);
  memcpy(dst_ip, ip6, sizeof(dst_ip));
}

struct Stats {
  // From http://www.iana.org/assignments/ipfix/ipfix.xhtml
  enum FinishedType {
    IDLE_TIMEOUT =
        1,  // The Flow was terminated because it was considered to be idle.
    ACTIVE_TIMEOUT = 2,  // The Flow was terminated for reporting purposes while
                         // it was still active, for example, after the maximum
                         // lifetime of unreported Flows was reached.
    END_DETECTED = 3,    // The Flow was terminated because the Metering Process
                         // detected signals indicating the end of the Flow, for
                         // example, the TCP FIN flag.
    FORCED_END = 4,  // The Flow was terminated because of some external event,
                     // for example, a shutdown of the Metering Process
                     // initiated by a network management application.
    LACK_OF_RESOURCES = 5,  // The Flow was terminated because of lack of
                            // resources available to the Metering Process
                            // and/or the Exporting Process.
  };
  Stats();
  Stats(uint64_t b, uint64_t p, uint64_t ts_ns);

  uint64_t bytes;
  uint64_t packets;
  uint8_t tcp_flags;
  uint64_t first_ns, last_ns;  // nanos since epoch

  const Stats& operator+=(const Stats& f);
  uint8_t Finished(uint64_t cutoff_ns) const {
    if (last_ns < cutoff_ns) {
      return IDLE_TIMEOUT;
    }
    if (tcp_flags & (0x01 /* FIN */ | 0x04 /* RST */)) {
      return END_DETECTED;
    }
    return ACTIVE_TIMEOUT;
  }
};

}  // namespace flow
}  // namespace clerk

namespace std {

template <>
struct hash<clerk::flow::Key> {
  size_t operator()(const clerk::flow::Key& k) const { return k.hash(); }
};

}  // namespace std

namespace clerk {
namespace flow {

typedef std::unordered_map<Key, Stats> Table;
const Stats& AddToTable(Table* t, const Key& key, const Stats& stats);
void CombineTable(Table* dst, const Table& src);

}  // namespace flow
}  // namespace clerk

#endif  // CLERK_FLOW_H_
