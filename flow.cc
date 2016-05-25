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
#include "flow.h"

#include <glog/logging.h>
#include <city.h>


namespace clerk {
namespace flow {

Key::Key() { memset(this, 0, sizeof(*this)); }

bool Key::operator==(const Key& other) const {
  return memcmp(this, &other, sizeof(Key)) == 0;
}

size_t Key::hash() const {
  return CityHash64(reinterpret_cast<const char*>(this), sizeof(*this));
}

Stats::Stats() { memset(this, 0, sizeof(*this)); }

Stats::Stats(uint64_t b, uint64_t p, uint64_t ts_ms)
    : bytes(b), packets(p), tcp_flags(0), first_ms(ts_ms), last_ms(ts_ms) {}

const Stats& Stats::operator+=(const Stats& f) {
  bytes += f.bytes;
  packets += f.packets;
  tcp_flags |= f.tcp_flags;
  if (!first_ms || first_ms > f.first_ms) first_ms = f.first_ms;
  if (!last_ms || last_ms < f.last_ms) last_ms = f.last_ms;
  return *this;
}

const Stats& AddToTable(Table* t, const Key& key, const Stats& stats) {
  auto finder = t->find(key);
  if (finder == t->end()) {
    auto emplaced = t->emplace(key, stats);
    return emplaced.first->second;
  }
  finder->second += stats;
  return finder->second;
}

void CombineTable(Table* dst, const Table& src) {
  for (const auto& iter : src) {
    AddToTable(dst, iter.first, iter.second);
  }
}

}  // namespace flow
}  // namespace clerk
