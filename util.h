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

#ifndef CLERK_UTIL_H_
#define CLERK_UTIL_H_

#include <string.h>

#include <condition_variable>
#include <mutex>

using namespace std;

class StringPiece {
 public:
  StringPiece() : data_(nullptr), size_(0) {}
  StringPiece(const char* data, size_t size) : data_(data), size_(size) {}
  const char* data() const { return data_; }
  size_t size() const { return size_; }
  char operator[](size_t i) const { return data_[i]; }
  bool operator==(const StringPiece& s) const {
    return s.size_ == size_ && memcmp(s.data_, data_, size_) == 0;
  }

 private:
  const char* data_;
  size_t size_;
};

class Notification {
 public:
  Notification() : done_(false) {}
  bool HasBeenNotified() {
    std::unique_lock<mutex> ml(mu_);
    return done_;
  }
  void Notify() {
    std::unique_lock<mutex> ml(mu_);
    done_ = true;
  }

 private:
  bool done_;
  std::mutex mu_;
  std::condition_variable cond_;
};

#define DISALLOW_COPY_AND_ASSIGN(Type) \
  Type(const Type&) {}                 \
  Type(const Type&&) {}                \
  void operator=(const Type&) {}
#define FALLTHROUGH_INTENDED \
  do {                       \
  } while (0)

extern struct timespec clerk_clock_realtime, clerk_clock_monotonic;
extern clockid_t clerk_clock_mono_id;
inline bool InitTime() {
  clock_gettime(CLOCK_REALTIME, &clerk_clock_realtime);
#ifdef CLOCK_MONOTONIC_RAW
  // If monotonic raw clock is supported and available, let's use that.
  if (!clock_gettime(CLOCK_MONOTONIC_RAW, &clerk_clock_monotonic)) {
    clerk_clock_mono_id = CLOCK_MONOTONIC_RAW;
    return true;
  }
#endif
  clock_gettime(CLOCK_MONOTONIC, &clerk_clock_monotonic);
  return true;
}
extern bool clerk_run_init_time;

const int64_t kNumMillisPerSecond = 1000LL;
const int64_t kNumNanosPerMilli = 1000000LL;
const int64_t kNumNanosPerSecond = 1000000000LL;

inline int64_t GetCurrentTimeNanos() {
  struct timespec tv;
  clock_gettime(clerk_clock_mono_id, &tv);
  int64_t secs =
      clerk_clock_realtime.tv_sec - clerk_clock_monotonic.tv_sec + tv.tv_sec;
  int64_t nsecs =
      clerk_clock_realtime.tv_nsec - clerk_clock_monotonic.tv_nsec + tv.tv_nsec;
  return secs * kNumNanosPerSecond + nsecs;
}
inline double GetCurrentTimeSeconds() {
  return GetCurrentTimeNanos() * 1.0L / kNumNanosPerSecond;
}

inline void SleepForNanoseconds(int64_t nanos) {
  if (nanos <= 0) {
    return;
  }
  struct timespec tv;
  tv.tv_sec = nanos / kNumNanosPerSecond;
  tv.tv_nsec = nanos % kNumNanosPerSecond;
  while (EINTR == clock_nanosleep(CLOCK_MONOTONIC, 0, &tv, &tv)) {
  }
}
inline void SleepForSeconds(double seconds) {
  SleepForNanoseconds(seconds * kNumNanosPerSecond);
}

#endif  // CLERK_UTIL_H_
