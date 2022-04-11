// MIT License
//
// Copyright (c) 2018 Xiao Wang (wangxiao@gmail.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// The following code has been adopted from
// https://github.com/emp-toolkit/emp-agmpc. It has been modified to define the
// class within a namespace and add additional methods (sendRelative,
// recvRelative).

#pragma once

#include <emp-tool/emp-tool.h>

#include <vector>

namespace io {
using namespace emp;

class NetIOMP {
 public:
  std::vector<NetIO*> ios;
  std::vector<NetIO*> ios2;
  int party;
  std::vector<bool> sent;
  int num_parties;

  NetIOMP(int num_parties, int party, int port, char* IP[],
          bool localhost = false);
  ~NetIOMP();

  int64_t count();
  void resetStats();

  void send(int dst, const void* data, size_t len);
  void sendRelative(int offset, const void* data, size_t len);
  void sendBool(int dst, const bool* data, size_t len);
  void sendBoolRelative(int offset, const bool* data, size_t len);

  void recv(int src, void* data, size_t len);
  void recvRelative(int offset, void* data, size_t len);
  void recvBool(int src, bool* data, size_t len);
  void recvRelative(int offset, bool* data, size_t len);

  NetIO*& get(size_t idx, bool b = false);

  NetIO*& getSendChannel(size_t idx);
  NetIO*& getRecvChannel(size_t idx);

  void flush(int idx = -1);
  void sync();
};
};  // namespace io
