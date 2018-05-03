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

#include <testimony.h>
#include <glog/logging.h>

#include "stringpiece.h"
#include "testimony.h"

namespace clerk {

Packet::Packet(const struct tpacket3_hdr* hdr) : hdr_(hdr) {
  headers_.Parse(data());
}

StringPiece Packet::data() const {
  return StringPiece(reinterpret_cast<const char*>(testimony_packet_data(hdr_)),
                     hdr_->tp_snaplen);
}

int64_t Packet::ts_nanos() const { return testimony_packet_nanos(hdr_); }

TestimonyProcessor::TestimonyProcessor(const string& socket,
                                       const StateFactory* states)
    : socket_(socket), states_(states) {}

void TestimonyProcessor::StartThreads() {
  CHECK_EQ(0, threads_.size());
  testimony t;
  LOG(INFO) << "Initial connection to testimony socket " << socket_;
  CHECK_EQ(0, testimony_connect(&t, socket_.c_str()));
  for (int i = 0; i < testimony_conn(t)->fanout_size; i++) {
    LOG(INFO) << "Starting testimony thread " << i;
    testimony thread_t;
    CHECK_EQ(0, testimony_connect(&thread_t, socket_.c_str()));
    testimony_conn(thread_t)->fanout_index = i;
    CHECK_EQ(0, testimony_init(thread_t)) << testimony_error(thread_t);
    threads_.emplace_back(std::unique_ptr<TestimonyThread>(
        new TestimonyThread(thread_t, states_->New(nullptr), &last_)));
  }
  testimony_close(t);
}

void TestimonyProcessor::Gather(std::vector<std::unique_ptr<State>>* states,
                                bool last) {
  CHECK_NE(0, threads_.size());
  CHECK(!last_.HasBeenNotified());
  if (last) {
    LOG(INFO) << "Final TestimonyProcessor gather, stopping threads";
    last_.Notify();
    for (size_t i = 0; i < threads_.size(); i++) {
      LOG(INFO) << "Waiting for thread " << i;
      threads_[i]->Join();
      LOG(INFO) << "Thread " << i << " completed";
    }
  }
  states->clear();
  LOG(INFO) << "Gathering state from " << threads_.size() << " threads";
  states->resize(threads_.size());
  for (size_t i = 0; i < threads_.size(); i++) {
    (*states)[i] = threads_[i]->SwapState(states_);
  }
}

TestimonyProcessor::~TestimonyProcessor() { CHECK(last_.HasBeenNotified()); }

std::unique_ptr<State> TestimonyThread::SwapState(const StateFactory* states) {
  std::unique_lock<std::mutex> ml(mu_);
  auto next = states->New(state_.get());
  state_.swap(next);
  return next;
}

void TestimonyThread::Run() {
  testimony_iter iter;
  CHECK_EQ(0, testimony_iter_init(&iter));
  while (!last_->HasBeenNotified()) {
    const struct tpacket_block_desc* block;
    CHECK_EQ(0, testimony_get_block(t_, 1000, &block)) << testimony_error(t_);
    if (!block) {
      VLOG(1) << "Timed out waiting for testimony block";
      continue;
    }
    VLOG(1) << "Got testimony block";
    CHECK_EQ(0, testimony_iter_reset(iter, block));
    const struct tpacket3_hdr* hdr;
    while ((hdr = testimony_iter_next(iter)) != nullptr) {
      Packet p(hdr);
      std::unique_lock<std::mutex> ml(mu_);
      state_->Process(p);
    }
    CHECK_EQ(0, testimony_return_block(t_, block)) << testimony_error(t_);
  }
  CHECK_EQ(0, testimony_iter_close(iter));
}

TestimonyThread::TestimonyThread(testimony t, std::unique_ptr<State> s,
                                 Notification* last)
    : state_(std::move(s)), t_(t), last_(last) {
  thread_.reset(new std::thread([this]() { Run(); }));
}

TestimonyThread::~TestimonyThread() {
  thread_->join();
  CHECK_EQ(0, testimony_close(t_));
}

}  // namespace clerk
