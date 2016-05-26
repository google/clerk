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

#ifndef CLERK_SEND_H_
#define CLERK_SEND_H_

#include <stdint.h>  // uint32_t, etc.
#include <stdlib.h>  // size_t

#include "flow.h"
#include "util.h"

namespace clerk {
namespace ipfix {

const size_t kMaxPacketSize = 1400;
const size_t kSingleRecordSize =
    16 + 16 +  // IPv6 addresses for ipv6.  IPv4 is 4+4, so this overestimates
               // in that case.
    2 + 2 +    // Ports
    1 +        // Protocol
    1 +        // TCP flags
    2 +        // ICMP code
    8 +        // Bytes
    8 +        // Packets
    8 +        // First millis since epoch, uint64
    8 +        // Last millis since epoch, uint64
    1 +        // IP TOS
    1 +        // Flow end reason
    2 +        // VLAN ID
    0;
const uint16_t kFieldCount = 14;
const size_t kHeaderSize = 20;
const size_t kFlowSetSize = 2 * 2 +           // Template ID, field count
                            kFieldCount * 4;  // 14 fields

// Pulled from http://www.ietf.org/rfc/rfc3954.txt
enum IpfixTypes {
  IN_BYTES = 1,
  IN_PKTS = 2,
  PROTOCOL = 4,
  IP_CLASS_OF_SERVICE = 5,
  TCP_FLAGS = 6,
  L4_SRC_PORT = 7,
  IPV4_SRC_ADDR = 8,
  L4_DST_PORT = 11,
  IPV4_DST_ADDR = 12,
  IPV6_SRC_ADDR = 27,
  IPV6_DST_ADDR = 28,
  ICMP_TYPE = 32,
  VLAN_ID = 58,
  FLOW_END_REASON = 136,
  FLOW_START_NANOSECONDS = 156,
  FLOW_END_NANOSECONDS = 157,
};

enum PacketType {
  PT_V4 = 256,
  PT_V6 = 257,
  PT_TEMPLATE = 2,
};

// IPFIXPacket is a helper to build an IPFIX (netflow v10) packet to send over
// the network.  It's a little tricky, so read all the fine print... or just use
// IPFIX::Send instead  ;)
class IPFIXPacket {
 public:
  // Creates a new packet with the given uptime and current time.
  explicit IPFIXPacket(uint32_t unix_secs);

  // Reset this pcket to a packet type.  If that packet type is PT_TEMPLATE, the
  // packet is immediately sendable, and AddToBuffer will CHECK-fail.
  // Otherwise, AddToBuffer must be called before SendTo.
  void Reset(PacketType t, uint32_t seq);
  // Get the packet data to send.
  StringPiece PacketData();
  // Send packet data to socket.
  void SendTo(int sock_fd);
  // Number of entries added to the buffer.
  int count() const;
  // AddToBuffer adds the given key/flow to the packet.  If the packet is full
  // and must be immediately sent, returns true.
  bool AddToBuffer(const flow::Key& k, const flow::Stats& f,
                   uint8_t end_reason);

  // Writes the template for v4 or v6 to the packet.  Should be called only once
  // on a single packet, packet type must be PT_TEMPLATE.
  void WriteFlowSet(bool v4);

 private:
  char buffer_[kMaxPacketSize];
  char* start_;
  char* record_buf_;
  char* current_;
  char* limit_;
  uint16_t count_;
  PacketType type_;
  uint32_t unix_secs_;
};

}  // namespace ipfix
}  // namespace clerk

#endif  // CLERK_SEND_H_
