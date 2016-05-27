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

#include <string>

#include <gtest/gtest.h>
#include "asn_map.h"

namespace clerk {

class CSVTest : public ::testing::Test {};

TEST_F(CSVTest, TestNext) {
  char input[] = "ABC,DEF,GHI,JKL,MNOP,QRS";
  char* val = input;
  const char* want[] = {
      "ABC", "DEF", "GHI", "JKL", "MNOP", "QRS",
  };
  int want_size = sizeof(want) / sizeof(*want);
  for (int i = 0; i < want_size; i++) {
    char* got = internal::NextCSVValue(&val);
    EXPECT_EQ(std::string(want[i]), std::string(got));
  }
  EXPECT_EQ(internal::NextCSVValue(&val), nullptr);
}

class ASNMapTest : public ::testing::Test {};

TEST_F(ASNMapTest, TestBasic) {
  uint8_t ipA[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint8_t ipAB[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3};
  uint8_t ipB[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
  uint8_t ipC[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
  uint8_t ipCD[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3};
  uint8_t ipD[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff};
  uint8_t ipDE[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0xff, 0xff};
  uint8_t ipE[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};
  uint8_t ipEF[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 3};
  uint8_t ipF[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff, 0xff};
  uint8_t ipG[] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff, 0xff};

  ASNMap m;
  m.Add(ipE, ipF, 3);
  m.Add(ipA, ipB, 1);
  m.Add(ipG, ipG, 4);
  m.Add(ipC, ipD, 2);

  // Check in-between values
  EXPECT_EQ(m.ASN(ipAB), 1);
  EXPECT_EQ(m.ASN(ipCD), 2);
  EXPECT_EQ(m.ASN(ipDE), ASNMap::NoASN);
  EXPECT_EQ(m.ASN(ipEF), 3);

  // Check boundaries
  EXPECT_EQ(m.ASN(ipA), 1);
  EXPECT_EQ(m.ASN(ipB), 1);
  EXPECT_EQ(m.ASN(ipC), 2);
  EXPECT_EQ(m.ASN(ipD), 2);
  EXPECT_EQ(m.ASN(ipE), 3);
  EXPECT_EQ(m.ASN(ipF), 3);
  EXPECT_EQ(m.ASN(ipG), 4);
}

}  // namespace clerk
