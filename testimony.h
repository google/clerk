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

#ifndef CLERK_TESTIMONY_H_
#define CLERK_TESTIMONY_H_

// Provides bindings to get packets from Testimony, and a method for gathering
// state from multiple packets, then combining it.

#include <linux/if_packet.h>
#include <testimony.h>

#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "headers.h"
#include "util.h"
#include "stringpiece.h"

// TODO(user):  Use namespace access::security::clerk.
namespace clerk {

class Packet;

// State is a user-defined class for gathering state from a stream of packets.
class State {
 public:
  State() {}
  virtual ~State() {}
  virtual void Process(const Packet& p) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(State);
};

// StateFactory creates new states.
class StateFactory {
 public:
  virtual ~StateFactory() {}
  virtual std::unique_ptr<State> New(const State* old) const = 0;
};

template <class T>
class EmptyConstructorFactory : public StateFactory {
 public:
  std::unique_ptr<State> New(const State* old) const override {
    return std::unique_ptr<State>(new T());
  }
};

template <class T>
class SelfConstructorFactory : public StateFactory {
 public:
  std::unique_ptr<State> New(const State* old) const override {
    return std::unique_ptr<State>(new T(reinterpret_cast<const T*>(old)));
  }
};

class TestimonyThread;

// TestimonyProcessor runs TestimonyThreads and gathers states from
// them.
class TestimonyProcessor {
 public:
  TestimonyProcessor(const string& socket, const StateFactory* states);
  virtual ~TestimonyProcessor();

  void StartThreads();
  // Gather all states currently in threads, replacing them with empty ones.
  // Note that Gather with last=true MUST be called before TestimonyProcessor is
  // destructed, to stop all threads and gather their final state.
  // Also, StartThreads must be called first, one time, before the first Gather
  // call.
  void Gather(std::vector<std::unique_ptr<State>>* states, bool last);

 private:
  const string socket_;
  const StateFactory* states_;
  std::vector<std::unique_ptr<TestimonyThread>> threads_;
  Notification last_;
  DISALLOW_COPY_AND_ASSIGN(TestimonyProcessor);
};

// TestimonyThread is internal to TestimonyProcessor.  It gathers state on a
// single testimony stream.
class TestimonyThread {
 public:
  TestimonyThread(testimony t, std::unique_ptr<State> s, Notification* last);
  ~TestimonyThread();
  std::unique_ptr<State> SwapState(const StateFactory* states);
  void Join() { thread_->join(); }

 private:
  void Run();

  std::mutex mu_;
  std::unique_ptr<State> state_;
  testimony t_;
  Notification* last_;
  std::unique_ptr<std::thread> thread_;
};

// Packet provides data on a single testimony packet.
class Packet {
 public:
  virtual ~Packet() {}
  StringPiece data() const;
  int64_t ts_nanos() const;
  const struct tpacket3_hdr* hdr() const { return hdr_; }
  const Headers& headers() const { return headers_; }

 private:
  friend class TestimonyThread;
  explicit Packet(const struct tpacket3_hdr* hdr);
  const struct tpacket3_hdr* hdr_;
  Headers headers_;
  DISALLOW_COPY_AND_ASSIGN(Packet);
};

}  // namespace clerk

#endif  // CLERK_TESTIMONY_H_
