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

#ifndef CLERK_STRINGPIECE_H_
#define CLERK_STRINGPIECE_H_


namespace clerk {

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

}  // namespace clerk

#endif  // CLERK_STRINGPIECE_H_
