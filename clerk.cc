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

#include <arpa/inet.h>
#include <stdio.h>

#include <memory>
#include <thread>

#include <gflags/gflags.h>
#include "asn_map.h"
#include "ipfix.h"
#include "testimony.h"

#include "util.h"

using google::ParseCommandLineFlags;

DEFINE_string(testimony, "", "Name of testimony socket");
DEFINE_string(collector, "127.0.0.1:6555", "Socket address of collector");
DEFINE_double(upload_every_secs, 60, "Upload IPFIX to collector once every X");
DEFINE_double(flow_timeout_secs, 60 * 5, "Time out flows after X");
DEFINE_string(asns_csv, "",
              "Filename of ASN CSV file.  See *_asns.py for ways to get ASN "
              "data readable by clerk.");
DEFINE_double(asns_reread_every_secs, 86400,
              "Reread ASN CSV file once every X seconds");

// CombineGather parallelizes the process of combining multiple IPFIX states
// together, by synchronously combining half of them with the other half, until
// there's only one left.
void CombineGather(std::vector<std::unique_ptr<clerk::State>>* states) {
  while (states->size() > 1) {
    std::vector<std::thread> threads;
    // New size is 1/2 the old size, rounded up.
    int new_size = states->size() / 2 + states->size() % 2;
    LOG(INFO) << "Combining " << states->size() << " states into " << new_size;
    for (int i = 0; i < new_size; i++) {
      size_t other = i + new_size;
      if (other < states->size()) {  // not always true, if states.size() is odd
        threads.emplace_back(std::thread([states, i, other]() {
          // Actual combination implemented with += operator.
          *reinterpret_cast<clerk::IPFIX*>((*states)[i].get()) +=
              *reinterpret_cast<clerk::IPFIX*>((*states)[other].get());
        }));
      }
    }
    for (size_t i = 0; i < threads.size(); i++) {
      threads[i].join();
    }
    // Now throw away the second half, since it was combined with the first
    // and is now redundant.
    states->resize(new_size);
  }
}

void AddASNsTo(clerk::flow::Table* t, const clerk::ASNMap& asns) {
  LOG(INFO) << "Adding ASNs to flows";
  for (auto iter = t->begin(); iter != t->end(); ++iter) {
    iter->second.src_asn = asns.ASN(iter->first.src_ip);
    iter->second.dst_asn = asns.ASN(iter->first.dst_ip);
  }
}

// Convert a socket address to a sockaddr_storage.
// This is quick and dirty, and could definitely use some work.
// Right now, it supports 2 formats:
//   192.168.1.2:3333 (IPv4:Port)
//   [2001::0123]:4444 ([IPv6]:Port)
void StringToSocketStorage(const std::string& addr, struct sockaddr_storage* ss,
                           socklen_t* size) {
  memset(ss, 0, sizeof(*ss));
  string mutable_addr = addr;
  CHECK_GT(mutable_addr.size(), 1);
  auto colon = mutable_addr.find_last_of(':');
  CHECK_NE(colon, std::string::npos);
  mutable_addr[colon] = '\0';  // make string before colon null-terminated
  int port = atoi(mutable_addr.data() + colon + 1);
  if (mutable_addr[0] == '[') {  // v6
    auto ip6end = mutable_addr.find_first_of(']');
    CHECK_NE(ip6end, std::string::npos);
    mutable_addr[ip6end] = '\0';
    CHECK_EQ(ip6end + 1, colon);
    auto in6 = reinterpret_cast<struct sockaddr_in6*>(ss);
    in6->sin6_port = htons(port);
    in6->sin6_family = AF_INET6;
    // We add 1 to data() to skip over initial '[' char.
    CHECK_EQ(1, inet_pton(AF_INET6, mutable_addr.data() + 1, &in6->sin6_addr));
    *size = sizeof(struct sockaddr_in6);
  } else {  // v4
    auto in4 = reinterpret_cast<struct sockaddr_in*>(ss);
    in4->sin_port = htons(port);
    in4->sin_family = AF_INET;
    CHECK_EQ(1, inet_pton(AF_INET, mutable_addr.data(), &in4->sin_addr));
    *size = sizeof(struct sockaddr_in);
  }
}

void ReadASNs(clerk::ASNMap* map) {
  if (!FLAGS_asns_csv.empty()) {
    LOG(INFO) << "Reading ASNs from " << FLAGS_asns_csv;
    auto f = fopen(FLAGS_asns_csv.c_str(), "r");
    PCHECK(f != nullptr) << "Failed to open " << FLAGS_asns_csv;
    map->Clear();
    clerk::LoadFromCSV(map, f);
    fclose(f);
  }
}

int main(int argc, char** argv) {
  ParseCommandLineFlags(&argc, &argv, true);
  clerk::ASNMap asns;
  ReadASNs(&asns);
  double last_asn_read_secs = GetCurrentTimeSeconds();

  clerk::IPFIXFactory factory;

  std::unique_ptr<clerk::Sender> sender;
  if (FLAGS_collector == "stdout") {
    sender.reset(new clerk::FileSender(stdout, &factory));
  } else {
    struct sockaddr_storage ss;
    socklen_t ss_size;
    StringToSocketStorage(FLAGS_collector, &ss, &ss_size);
    int fd = socket(ss.ss_family, SOCK_DGRAM, 0);
    PCHECK(connect(fd, reinterpret_cast<sockaddr*>(&ss), ss_size) >= 0)
        << "Connect to " << FLAGS_collector << " failed";
    sender.reset(new clerk::PacketSender(fd, &factory));
  }

  clerk::TestimonyProcessor processor(FLAGS_testimony, &factory);
  double last_upload_secs = GetCurrentTimeSeconds();
  processor.StartThreads();
  while (1) {
    SleepForSeconds(last_upload_secs + FLAGS_upload_every_secs -
                    GetCurrentTimeSeconds());
    last_upload_secs = GetCurrentTimeSeconds();
    factory.SetCutoffNanos((last_upload_secs - FLAGS_flow_timeout_secs) *
                           kNumNanosPerSecond);
    std::vector<std::unique_ptr<clerk::State>> states;
    processor.Gather(&states, false);
    CombineGather(&states);
    clerk::IPFIX* first = reinterpret_cast<clerk::IPFIX*>(states[0].get());
    clerk::flow::Table f;
    first->SwapFlows(&f);
    AddASNsTo(&f, asns);
    sender->Send(f);
    if (last_upload_secs - last_asn_read_secs > FLAGS_asns_reread_every_secs) {
      last_asn_read_secs = last_upload_secs;
      ReadASNs(&asns);
    }
  }
}
