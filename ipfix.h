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

#ifndef CLERK_IPFIX_H_
#define CLERK_IPFIX_H_

#include "flow.h"
#include "testimony.h"

namespace clerk {

class IPFIXFactory;

class Sender {
 public:
  Sender() {}
  virtual ~Sender() {}
  virtual void Send(const flow::Table& flows) = 0;
};

class PacketSender : public Sender {
 public:
  PacketSender(int sock_fd, const IPFIXFactory* fact)
      : factory_(fact), fd_(sock_fd), seq_(0) {}
  ~PacketSender() override {}

  void Send(const flow::Table& flows) override;

 private:
  const IPFIXFactory* factory_;
  int fd_;
  uint32_t seq_;
};

class FileSender : public Sender {
 public:
  explicit FileSender(FILE* f, const IPFIXFactory* fact)
      : factory_(fact), f_(f) {}
  ~FileSender() override {}

  void Send(const flow::Table& flows) override;

 private:
  const IPFIXFactory* factory_;
  FILE* f_;
};

// IPFIX gathers IPFIX statistics about network flows, then provides a method
// (SendTo) to send them via UDP over a network socket.
class IPFIX : public State {
 public:
  // Create a new IPFIX.  If 'old' is non-null, it contains the previous state
  // for this thread, which we aggregate into the new state.
  IPFIX(const IPFIX* old, const IPFIXFactory* f);
  ~IPFIX() override {}

  // Process implements clerk::State by updating our flow table.
  void Process(const Packet& p) override;
  // += aggregates multiple IPFIX states together.
  void operator+=(const IPFIX& other);

  void SwapFlows(flow::Table* f) { f->swap(flows_); }

 private:
  flow::Table flows_;
  const IPFIXFactory* factory_;

  DISALLOW_COPY_AND_ASSIGN(IPFIX);
};

class IPFIXFactory : public StateFactory {
 public:
  IPFIXFactory() : flow_timeout_cutoff_ns_(0) {}
  ~IPFIXFactory() override {}

  std::unique_ptr<State> New(const State* old) const override {
    return std::unique_ptr<State>(
        new IPFIX(reinterpret_cast<const IPFIX*>(old), this));
  }
  void SetCutoffNanos(uint64_t ms) { flow_timeout_cutoff_ns_ = ms; }
  uint64_t CutoffNanos() const { return flow_timeout_cutoff_ns_; }

 private:
  uint64_t flow_timeout_cutoff_ns_;
};

}  // namespace clerk

#endif  // CLERK_IPFIX_H_
