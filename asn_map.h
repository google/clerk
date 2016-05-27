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

#ifndef CLERK_ASN_MAP_H_
#define CLERK_ASN_MAP_H_

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <set>
#include <vector>

namespace clerk {

class ASNMap {
 public:
  ASNMap();
  ~ASNMap();
  // from and to must point to 16-byte IP addresses.  IPv4 addresses must be
  // IPv4-mapped IPv6 addresses in the lowest-order bytes (e.g. ::192.168.1.1).
  void Add(const uint8_t* from, const uint8_t* to, uint32_t asn);

  // addr must point to a 16-byte IP address.  IPv4 addresses must be
  // IPv4-mapped IPv6 addresses in the lowest-order bytes (e.g. ::192.168.1.1).
  // Returns NoASN if not found.
  uint32_t ASN(const uint8_t* addr) const;

  // Clear removes all current mapping from this map.
  void Clear() { set_.clear(); }

  static const uint32_t NoASN;  // == 0

 private:
  struct Range {
    Range() { memset(this, 0, sizeof(Range)); }
    Range(const uint8_t* a, const uint8_t* b, uint32_t n);
    Range(const uint8_t* b) : Range() { memcpy(to, b, 16); }  // for finds
    bool Contains(const uint8_t* addr) const;
    bool operator<(const Range& r) const {
      // We order based on the 'to' address (the higher of from and to), so that
      // set::lower_bound will immediately return the only range candidate which
      // might contain an address.
      return ASNMap::Compare(to, r.to) < 0;
    }

    uint8_t from[16];
    uint8_t to[16];
    uint32_t asn;
  };

  static inline int Compare(const uint8_t* a, const uint8_t* b) {
    return memcmp(a, b, 16);
  }

  std::set<Range> set_;
};

// Load CSV of IP ranges and ASNs.  Example file lines:
//   ::,::ffff,1234
//   ::1:0,2001::,4567
// Each line contains a start and limit IP address, and an ASN.
// IPs are mapped to ASNs using these (non-overlapping, inclusive) ranges.
// IPv4 addresses are mapped in the range ::0000:0000 - ::FFFF:FFFF.
void LoadFromCSV(ASNMap* to, FILE* f);

namespace internal {  // exposed just for testing.

char* NextCSVValue(char** val);

}  // internal

}  // namespace clerk

#endif  // CLERK_ASN_MAP_H_
