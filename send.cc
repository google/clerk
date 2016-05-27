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

#include "send.h"

#include <sys/socket.h>
#include <glog/logging.h>

namespace clerk {
namespace ipfix {

static inline void WriteChars(char** buffer, uint8_t a, uint8_t b, uint8_t c,
                              uint8_t d) {
  char* buf = *buffer;
  buf[0] = a;
  buf[1] = b;
  buf[2] = c;
  buf[3] = d;
  *buffer += 4;
}

static inline void WriteBE32(char** buffer, uint32_t data) {
  WriteChars(buffer, data >> 24, data >> 16, data >> 8, data);
}

static inline void WriteBE16s(char** buffer, uint16_t first, uint16_t second) {
  WriteChars(buffer, first >> 8, first, second >> 8, second);
}

static inline void WriteBE64(char** buffer, uint64_t v) {
  WriteBE32(buffer, v >> 32);
  WriteBE32(buffer, v & 0xFFFFFFFF);
}

IPFIXPacket::IPFIXPacket(uint32_t unix_secs) : unix_secs_(unix_secs) {}

void IPFIXPacket::Reset(PacketType t, uint32_t seq) {
  count_ = 0;
  type_ = t;
  memset(buffer_, 0, kMaxPacketSize);
  start_ = &buffer_[0];
  current_ = &buffer_[0];
  limit_ = start_ + kMaxPacketSize;

  CHECK_LE(current_ + kHeaderSize, limit_);
  char* want = current_ + kHeaderSize;
  WriteBE16s(&current_, 0xffff, 0xffff);  // Will rewrite in SendTo.
  WriteBE32(&current_, unix_secs_);
  WriteBE32(&current_, seq);
  WriteBE32(&current_, 12345);  // Source ID
  record_buf_ = current_;
  WriteBE16s(&current_, 0xffff, 0xffff);  // Will rewrite in SendTo.
  CHECK_EQ(current_, want) << "diff: " << current_ - buffer_;
}
StringPiece IPFIXPacket::PacketData() {
  CHECK(record_buf_ != nullptr);
  WriteBE16s(&record_buf_, type_, current_ - record_buf_);
  char* first = start_;
  WriteBE16s(&first, 10, current_ - start_);
  return StringPiece(buffer_, current_ - buffer_);
}

void IPFIXPacket::SendTo(int sock_fd) {
  auto data = PacketData();
  if (send(sock_fd, data.data(), data.size(), 0) < 0) {
    PLOG(ERROR) << "Sending packet to socket failed";
  }
}

int IPFIXPacket::count() const { return count_; }

bool IPFIXPacket::AddToBuffer(const flow::Key& k, const flow::Stats& f,
                              uint8_t end_reason) {
  CHECK_LE(current_ + kSingleRecordSize, limit_);
  char* want = current_ + kSingleRecordSize;
  count_++;
  switch (type_) {
    case ipfix::PT_V4:
      CHECK_EQ(k.network, 4);
      WriteBE32(&current_, k.get_src_ip4());
      WriteBE32(&current_, k.get_dst_ip4());
      break;
    case ipfix::PT_V6:
      CHECK_EQ(k.network, 6);
      memcpy(current_, k.src_ip, 16);
      current_ += 16;
      memcpy(current_, k.dst_ip, 16);
      current_ += 16;
      break;
    case ipfix::PT_TEMPLATE:
      LOG(FATAL) << "Adding to template";
    default:
      LOG(FATAL) << "Bad packet type " << type_;
  }
  WriteBE16s(&current_, k.src_port, k.dst_port);
  WriteChars(&current_, k.protocol, f.tcp_flags, k.icmp_type, k.icmp_code);
  WriteBE32(&current_, f.src_asn);
  WriteBE32(&current_, f.dst_asn);
  WriteBE64(&current_, f.bytes);
  WriteBE64(&current_, f.packets);
  WriteBE64(&current_, f.first_ns);
  WriteBE64(&current_, f.last_ns);
  WriteChars(&current_, k.tos, end_reason, k.vlan >> 8, k.vlan);
  CHECK_LE(current_, want);
  return current_ + kSingleRecordSize >= limit_;
}

void IPFIXPacket::WriteFlowSet(bool v4) {
  count_++;
  CHECK_EQ(type_, ipfix::PT_TEMPLATE);
  CHECK_LE(current_ + kFlowSetSize, limit_);
  char* want = current_ + kFlowSetSize;
  WriteBE16s(&current_, v4 ? ipfix::PT_V4 : ipfix::PT_V6,
             kFieldCount);  // template ID, field count
  if (v4) {
    WriteBE16s(&current_, IPV4_SRC_ADDR, 4);
    WriteBE16s(&current_, IPV4_DST_ADDR, 4);
  } else {
    WriteBE16s(&current_, IPV6_SRC_ADDR, 16);
    WriteBE16s(&current_, IPV6_DST_ADDR, 16);
  }
  WriteBE16s(&current_, L4_SRC_PORT, 2);
  WriteBE16s(&current_, L4_DST_PORT, 2);
  WriteBE16s(&current_, PROTOCOL, 1);
  WriteBE16s(&current_, TCP_FLAGS, 1);
  WriteBE16s(&current_, ICMP_TYPE, 2);
  WriteBE16s(&current_, BGP_SOURCE_AS_NUMBER, 4);
  WriteBE16s(&current_, BGP_DESTINATION_AS_NUMBER, 4);
  WriteBE16s(&current_, IN_BYTES, 8);
  WriteBE16s(&current_, IN_PKTS, 8);
  WriteBE16s(&current_, FLOW_START_NANOSECONDS, 8);
  WriteBE16s(&current_, FLOW_END_NANOSECONDS, 8);
  WriteBE16s(&current_, IP_CLASS_OF_SERVICE, 1);
  WriteBE16s(&current_, FLOW_END_REASON, 1);
  WriteBE16s(&current_, VLAN_ID, 2);
  CHECK_EQ(current_, want);
}

}  // namespace ipfix
}  // namespace clerk
