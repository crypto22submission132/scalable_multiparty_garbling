#include "netmp.hpp"

namespace io {
using namespace emp;

NetIOMP::NetIOMP(int num_parties, int party, int port, char* IP[],
                 bool localhost)
    : num_parties(num_parties),
      ios(num_parties),
      ios2(num_parties),
      sent(num_parties, false),
      party{party} {
  for (int i = 0; i < num_parties; ++i) {
    for (int j = i + 1; j < num_parties; ++j) {
      if (i == party) {
        usleep(1000);
        if (localhost) {
          ios[j] = new NetIO("127.0.0.1", port + i * num_parties + j, true);
        } else {
          ios[j] = new NetIO(IP[j], port + 2 * (i), true);
        }
        ios[j]->set_nodelay();

        usleep(1000);
        if (localhost) {
          ios2[j] = new NetIO(nullptr, port + j * num_parties + i, true);
        } else {
          ios2[j] = new NetIO(nullptr, port + 2 * (j) + 1, true);
        }
        ios2[j]->set_nodelay();
      } else if (j == party) {
        usleep(1000);
        if (localhost) {
          ios[i] = new NetIO(nullptr, port + i * num_parties + j, true);
        } else {
          ios[i] = new NetIO(nullptr, port + 2 * (i), true);
        }
        ios[i]->set_nodelay();

        usleep(1000);
        if (localhost) {
          ios2[i] = new NetIO("127.0.0.1", port + j * num_parties + i, true);
        } else {
          ios2[i] = new NetIO(IP[i], port + 2 * (j) + 1, true);
        }
      }
    }
  }
}

int64_t NetIOMP::count() {
  int64_t res = 0;
  for (int i = 0; i < num_parties; ++i)
    if (i != party) {
      res += ios[i]->counter;
      res += ios2[i]->counter;
    }
  return res;
}

void NetIOMP::resetStats() {
  for (int i = 0; i < num_parties; ++i) {
    if (i != party) {
      ios[i]->counter = 0;
      ios2[i]->counter = 0;
    }
  }
}

NetIOMP::~NetIOMP() {
  for (int i = 0; i < num_parties; ++i)
    if (i != party) {
      delete ios[i];
      delete ios2[i];
    }
}

void NetIOMP::send(int dst, const void* data, size_t len) {
  if (dst != -1 and dst != party) {
    if (party < dst)
      ios[dst]->send_data(data, len);
    else
      ios2[dst]->send_data(data, len);
    sent[dst] = true;
  }
#ifdef __clang__
  flush(dst);
#endif
}

void NetIOMP::sendRelative(int offset, const void* data, size_t len) {
  int dst = (party + offset) % num_parties;
  if (dst < 0) {
    dst += num_parties;
  }
  send(dst, data, len);
}

void NetIOMP::sendBool(int dst, const bool* data, size_t len) {
  for (int i = 0; i < len;) {
    uint64_t tmp = 0;
    for (int j = 0; j < 64 && i < len; ++i, ++j) {
      if (data[i]) {
        tmp |= (0x1ULL << j);
      }
    }
    send(dst, &tmp, 8);
  }
}

void NetIOMP::sendBoolRelative(int offset, const bool* data, size_t len) {
  int dst = (party + offset) % num_parties;
  if (dst < 0) {
    dst += num_parties;
  }
  sendBool(dst, data, len);
}

void NetIOMP::recv(int src, void* data, size_t len) {
  if (src != -1 && src != party) {
    if (sent[src]) flush(src);
    if (src < party)
      ios[src]->recv_data(data, len);
    else
      ios2[src]->recv_data(data, len);
  }
}

void NetIOMP::recvRelative(int offset, void* data, size_t len) {
  int src = (party + offset) % num_parties;
  if (src < 0) {
    src += num_parties;
  }
  recv(src, data, len);
}

void NetIOMP::recvBool(int src, bool* data, size_t len) {
  for (int i = 0; i < len;) {
    uint64_t tmp = 0;
    recv(src, &tmp, 8);
    for (int j = 63; j >= 0 && i < len; ++i, --j) {
      data[i] = (tmp & 0x1) == 0x1;
      tmp >>= 1;
    }
  }
}

void NetIOMP::recvRelative(int offset, bool* data, size_t len) {
  int src = (party + offset) % num_parties;
  if (src < 0) {
    src += num_parties;
  }
  recvBool(src, data, len);
}

NetIO*& NetIOMP::get(size_t idx, bool b) {
  if (b)
    return ios[idx];
  else
    return ios2[idx];
}

NetIO*& NetIOMP::getSendChannel(size_t idx) {
  if (party < idx) {
    return ios[idx];
  }

  return ios2[idx];
}

NetIO*& NetIOMP::getRecvChannel(size_t idx) {
  if (idx < party) {
    return ios[idx];
  }

  return ios2[idx];
}

void NetIOMP::flush(int idx) {
  if (idx == -1) {
    for (int i = 0; i < num_parties; ++i) {
      if (i != party) {
        ios[i]->flush();
        ios2[i]->flush();
      }
    }
  } else {
    if (party < idx) {
      ios[idx]->flush();
    } else {
      ios2[idx]->flush();
    }
  }
}

void NetIOMP::sync() {
  for (int i = 0; i < num_parties; ++i) {
    for (int j = 0; j < num_parties; ++j) {
      if (i < j) {
        if (i == party) {
          ios[j]->sync();
          ios2[j]->sync();
        } else if (j == party) {
          ios[i]->sync();
          ios2[i]->sync();
        }
      }
    }
  }
}
};  // namespace io
