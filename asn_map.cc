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

#include "asn_map.h"

#include <arpa/inet.h>

#include <string>

#include <glog/logging.h>

namespace clerk {

namespace {

// Useful for printf debugging :D
std::string IPAsString(const uint8_t* ip) {
  const uint8_t* u = reinterpret_cast<const uint8_t*>(ip);
  char buf[40];
  return std::string(
      buf, snprintf(buf, sizeof(buf),
                    "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%"
                    "02x%02x:%02x%02x",
                    u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9],
                    u[10], u[11], u[12], u[13], u[14], u[15]));
}

}  // namespace

const uint32_t ASNMap::NoASN = 0;

ASNMap::ASNMap() {}

ASNMap::~ASNMap() {}

void ASNMap::Add(const uint8_t* from, const uint8_t* to, uint32_t asn) {
  // from must be <= to.
  CHECK_LE(Compare(from, to), 0);
  CHECK_NE(asn, NoASN);
  // [from, to] should not intersect with any current range.
  auto found = set_.lower_bound(Range(to));
  if (found != set_.end()) {
    CHECK_LT(Compare(to, found->from), 0);
  }
  if (found != set_.begin()) {
    --found;
    CHECK_LT(Compare(found->to, from), 0);
  }
  Range r(from, to, asn);
  VLOG(1) << "Mapping range " << IPAsString(from) << " - " << IPAsString(to)
          << " to ASN " << asn;
  set_.emplace(r);
}

ASNMap::Range::Range(const uint8_t* a, const uint8_t* b, uint32_t n) : asn(n) {
  memcpy(from, a, 16);
  memcpy(to, b, 16);
}

bool ASNMap::Range::Contains(const uint8_t* addr) const {
  return Compare(from, addr) <= 0 && Compare(addr, to) <= 0;
}

uint32_t ASNMap::ASN(const uint8_t* addr) const {
  const auto& found = set_.lower_bound(Range(addr));
  if (found != set_.end() && found->Contains(addr)) {
    VLOG(2) << "Mapped " << IPAsString(addr) << " to ASN " << found->asn;
    return found->asn;
  }
  VLOG(2) << "Mapped " << IPAsString(addr) << " to NoASN (0)";
  return NoASN;
}

namespace internal {

// Pull out a CSV value from a line pointed to by *val.  Returns a
// null-terminated value string, and points *val past it so NextCSVValue may be
// called on it again.  Returns nullptr if unable to pull out a value.
char* NextCSVValue(char** val) {
  char* limit = *val + strlen(*val);
  if (*val == limit) {
    return nullptr;
  }
  char* out = *val;
  char* comma = strchr(*val, ',');
  if (comma) {
    *comma = '\0';
    *val = comma + 1;
  } else {
    *val = limit;
  }
  return out;
}

}  // namespace internal

void LoadFromCSV(ASNMap* to, FILE* f) {
  char line[1024];
  int lines = 0;
  while (fgets(line, sizeof(line), f) != nullptr) {
    lines++;
    char* next = line;
    char* startip = CHECK_NOTNULL(internal::NextCSVValue(&next));
    char* limitip = CHECK_NOTNULL(internal::NextCSVValue(&next));
    char* asn = CHECK_NOTNULL(internal::NextCSVValue(&next));
    uint8_t startaddr[16];
    uint8_t limitaddr[16];
    memset(startaddr, 0, sizeof(startaddr));
    memset(limitaddr, 0, sizeof(limitaddr));
    PCHECK(1 == inet_pton(AF_INET6, startip, startaddr));
    PCHECK(1 == inet_pton(AF_INET6, limitip, limitaddr));
    to->Add(startaddr, limitaddr, atoll(asn));
  }
  LOG(INFO) << "Read " << lines << " entries from ASN CSV";
}

}  // namespace clerk
