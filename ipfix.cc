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

#include <arpa/inet.h>   // inet_ntop
#include <netinet/in.h>  // INET6_ADDRSTRLEN

#include "ipfix.h"
#include "flow.h"
#include "send.h"
#include "util.h"

#include <glog/logging.h>

namespace clerk {

IPFIX::IPFIX(const IPFIX* other, const IPFIXFactory* f) : factory_(f) {
  CHECK(f != nullptr);
  if (other) {
    flows_ = other->flows_;
    for (auto iter = flows_.begin(); iter != flows_.end(); ) {
      if (iter->second.Finished(factory_->CutoffNanos()) ==
          flow::Stats::ACTIVE_TIMEOUT) {
        iter->second.packets = 0;
        iter->second.bytes = 0;
        iter->second.tcp_flags = 0;
        ++iter;
      } else {
        iter = flows_.erase(iter);
      }
    }
    // Should the number of flows we maintain shrink a lot, we'd like our memory
    // usage to decrease.  However, we don't want to have to
    // shrink/grow/shrink/grow our maps constantly.  So, we call 'reserve' on
    // our new map to shrink it to the size of our old map.  If the flows we
    // need in memory decrease, this will decrease the map's bucket size (which
    // otherwise was copied over via the copy constructor and will _not_
    // decrease ever).  However, since it does it based on the old size, we have
    // a bit of a buffer for size decreases.
    flows_.reserve(other->flows_.size());
    LOG(INFO) << "Retained " << flows_.size() << " from previous in "
              << flows_.bucket_count() << " buckets";
  }
}

void IPFIX::Process(const Packet& p) {
  flow::Key key;
  flow::Stats stats(p.hdr()->tp_len, 1, p.ts_nanos());

  // Layer 2-ish
  if (p.hdr()->tp_status & TP_STATUS_VLAN_VALID) {
    key.vlan = p.hdr()->hv1.tp_vlan_tci;
  }

  // Layer 3
  auto h = p.headers();
  if (h.ip4) {
    key.set_src_ip4(ntohl(h.ip4->saddr));
    key.set_dst_ip4(ntohl(h.ip4->daddr));
    key.protocol = h.ip4->protocol;
    key.network = 4;
    key.tos = h.ip4->tos >> 2;
  } else if (h.ip6) {
    key.protocol = h.ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    key.set_src_ip6(reinterpret_cast<const char*>(&h.ip6->ip6_src));
    key.set_dst_ip6(reinterpret_cast<const char*>(&h.ip6->ip6_dst));
    key.network = 6;
    key.tos = (h.ip6->ip6_flow & 0x0FC00000) >> 22;
  }

  // Layer 4
  if (h.tcp) {
    key.src_port = ntohs(h.tcp->th_sport);
    key.dst_port = ntohs(h.tcp->th_dport);
    stats.tcp_flags = h.tcp->th_flags;
  } else if (h.udp) {
    key.src_port = ntohs(h.udp->source);
    key.dst_port = ntohs(h.udp->dest);
  } else if (h.icmp4) {
    key.icmp_type = h.icmp4->type;
    key.icmp_code = h.icmp4->code;
  } else if (h.icmp6) {
    key.icmp_type = h.icmp6->icmp6_type;
    key.icmp_code = h.icmp6->icmp6_code;
  }

  flow::AddToTable(&flows_, key, stats);
  return;
}

void PacketSender::Send(const flow::Table& flows) {
  uint32_t unix_secs = GetCurrentTimeNanos() / kNumNanosPerSecond;
  LOG(INFO) << "FLUSHING " << flows.size() << " to " << fd_;
  ipfix::IPFIXPacket pkt(unix_secs);

  // Write IPv4 template and packets.
  LOG(INFO) << "Writing IPv4 template";
  pkt.Reset(ipfix::PT_TEMPLATE, seq_);
  pkt.WriteFlowSet(true);
  pkt.SendTo(fd_);

  pkt.Reset(ipfix::PT_V4, seq_);
  int ip4count = 0;
  for (auto iter : flows) {
    auto end_reason = iter.second.Finished(factory_->CutoffNanos());
    if (iter.first.network == 4 &&
        (iter.second.packets > 0 ||
         end_reason != flow::Stats::ACTIVE_TIMEOUT)) {
      ip4count++;
      seq_++;
      if (pkt.AddToBuffer(iter.first, iter.second, end_reason)) {
        pkt.SendTo(fd_);
        pkt.Reset(ipfix::PT_V4, seq_);
      }
    }
  }
  if (pkt.count()) {
    pkt.SendTo(fd_);
  }
  LOG(INFO) << "Wrote IPv4: " << ip4count;

  // Write IPv6 template and packets.
  LOG(INFO) << "Writing IPv6 template";
  pkt.Reset(ipfix::PT_TEMPLATE, seq_);
  pkt.WriteFlowSet(false);
  pkt.SendTo(fd_);

  pkt.Reset(ipfix::PT_V6, seq_);
  int ip6count = 0;
  for (auto iter : flows) {
    auto end_reason = iter.second.Finished(factory_->CutoffNanos());
    if (iter.first.network == 6 &&
        (iter.second.packets > 0 ||
         end_reason != flow::Stats::ACTIVE_TIMEOUT)) {
      ip6count++;
      seq_++;
      if (pkt.AddToBuffer(iter.first, iter.second, end_reason)) {
        pkt.SendTo(fd_);
        pkt.Reset(ipfix::PT_V6, seq_);
      }
    }
  }
  if (pkt.count()) {
    pkt.SendTo(fd_);
  }
  LOG(INFO) << "Wrote IPv6: " << ip6count;
}

static void WriteIPToBuffer(char* buf, int n, const uint8_t* ip, bool v4) {
  inet_ntop(v4 ? AF_INET : AF_INET6, ip + (v4 ? 12 : 0), buf, n);
}

void FileSender::Send(const flow::Table& flows) {
  char src_ip_buf[INET6_ADDRSTRLEN];
  char dst_ip_buf[INET6_ADDRSTRLEN];
  fprintf(f_,
          "FlowStart,FlowEnd,SrcIP,DstIP,SrcPort,DstPort,VLAN,TOS,Protocol,"
          "ICMPType,ICMPCode,Bytes,Packets\n");
  for (const auto& iter : flows) {
    auto end_reason = iter.second.Finished(factory_->CutoffNanos());
    auto key = iter.first;
    auto stats = iter.second;
    if (stats.packets > 0 || end_reason != flow::Stats::ACTIVE_TIMEOUT) {
      WriteIPToBuffer(src_ip_buf, sizeof(src_ip_buf), key.src_ip,
                      key.network == 4);
      WriteIPToBuffer(dst_ip_buf, sizeof(src_ip_buf), key.dst_ip,
                      key.network == 4);
      fprintf(f_, "%.9Lf,%.9Lf,%s,%s,%d,%d,%d,%d,%d,%d,%d,%lu,%lu,%d\n",
              stats.first_ns * 1.0L / kNumNanosPerSecond,
              stats.last_ns * 1.0L / kNumNanosPerSecond, src_ip_buf, dst_ip_buf,
              key.src_port, key.dst_port, key.vlan, key.tos, key.protocol,
              key.icmp_type, key.icmp_code, stats.bytes, stats.packets,
              end_reason);
    }
  }
  fflush(f_);
}

void IPFIX::operator+=(const IPFIX& other) {
  LOG(INFO) << "Adding " << other.flows_.size() << " flows into "
            << flows_.size();
  flow::CombineTable(&flows_, other.flows_);
}

}  // namespace clerk
