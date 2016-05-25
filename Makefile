# Copyright 2016 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

DEPS=Makefile *.h

CC=g++
CFLAGS=-std=c++0x -g -Wall -fno-strict-aliasing -fPIC -fPIE -pie -fstack-protector -D_FORTIFY_SOURCE=2 -rdynamic -O2 -Wno-narrowing
LDFLAGS=-Wl,-z,now -Wl,-z,relro
SHARED_LIBS=-ltestimony -lglog -lgflags -lcityhash
TEST_LIBS=-lgtest -lpthread
STATIC_LIBS=/usr/lib/x86_64-linux-gnu/libglog.a /usr/lib/libtestimony.a /usr/local/lib/libcityhash.a /usr/lib/x86_64-linux-gnu/libgflags.a

OBJECTS=flow.o headers.o ipfix.o send.o testimony.o util.o
TESTS=flow_test.o headers_test.o send_test.o

all: clerk

clean:
	rm -f *.o clerk core


### Building clerk, either in normal (g++) or sanitization (clang) modes ###

# Generate g++ object files.
%.o: %.cc $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Generate the clerk binary itself.  You mostly want this :)
clerk: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ clerk.cc $^ $(LDFLAGS) $(SHARED_LIBS)

.PHONY: test
test: $(OBJECTS) $(TESTS)
	$(CC) $(CFLAGS) -o $@ test_main.cc $^ $(LDFLAGS) $(SHARED_LIBS) $(TEST_LIBS) && ./test

clerk_static: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ clerk.cc $^ $(LDFLAGS) $(STATIC_LIBS)
