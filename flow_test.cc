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

#include <gtest/gtest.h>

#include "flow.h"

namespace clerk {
namespace flow {

class KeyTest : public ::testing::Test {};
class StatsTest : public ::testing::Test {};
class TableTest : public ::testing::Test {};

const char data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                     1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

TEST_F(KeyTest, TestCombine) {
  Key a;
  a.set_src_ip4(1);
  a.set_dst_ip4(2);
  a.src_port = 3;
  a.dst_port = 4;
  a.protocol = 5;
  Key b;
  b.set_src_ip4(1);
  b.set_dst_ip4(2);
  b.src_port = 3;
  b.dst_port = 4;
  b.protocol = 5;
  EXPECT_EQ(a, b);
#define EQMOD(field, val)          \
  do {                             \
    auto old = b.field;            \
    b.field = val;                 \
    EXPECT_NE(a, b);               \
    EXPECT_NE(a.hash(), b.hash()); \
    b.field = old;                 \
    EXPECT_EQ(a, b);               \
    EXPECT_EQ(a.hash(), b.hash()); \
  } while (0)
  EQMOD(src_port, 9);
  EQMOD(dst_port, 9);
  EQMOD(protocol, 9);
  EQMOD(network, 9);
  EQMOD(tos, 9);
  EQMOD(icmp_type, 9);
  EQMOD(icmp_code, 9);
#undef EQMOD

  a.set_src_ip4(0);
  a.set_dst_ip4(0);
  a.set_src_ip6(&data[0]);
  a.set_dst_ip6(&data[0]);
  EXPECT_NE(a, b);
  b.set_src_ip4(0);
  b.set_dst_ip4(0);
  b.set_src_ip6(&data[16]);
  b.set_dst_ip6(&data[16]);
  EXPECT_EQ(a, b);
}

TEST_F(StatsTest, TestIncrement) {
  Stats a(10, 1, 1000);
  EXPECT_EQ(a.bytes, 10);
  EXPECT_EQ(a.packets, 1);
  EXPECT_EQ(a.first_ms, 1000);
  EXPECT_EQ(a.last_ms, 1000);
  a += Stats(5, 2, 1500);
  EXPECT_EQ(a.bytes, 15);
  EXPECT_EQ(a.packets, 3);
  EXPECT_EQ(a.first_ms, 1000);
  EXPECT_EQ(a.last_ms, 1500);
  a += Stats(3, 4, 500);  // backwards in time, shouldn't probably happen
  EXPECT_EQ(a.bytes, 18);
  EXPECT_EQ(a.packets, 7);
  EXPECT_EQ(a.first_ms, 500);
  EXPECT_EQ(a.last_ms, 1500);
}

TEST_F(TableTest, TestAdd) {
  Table t;
  for (int i = 0; i < 100; i++) {
    for (int ip = 0; ip < 16; ip++) {
      Key a;
      a.set_src_ip6(&data[ip]);
      a.set_dst_ip6(&data[ip]);
      auto s = AddToTable(&t, a, Stats(i, i * 2, 1000));
      EXPECT_EQ(s.bytes, i * (i + 1) / 2);
      EXPECT_EQ(s.packets, i * (i + 1));
    }
  }
}

}  // namespace flow
}  // namespace clerk
