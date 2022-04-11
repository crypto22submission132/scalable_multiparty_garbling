#include <emp-tool/emp-tool.h>

#include <boost/format.hpp>
#include <boost/program_options.hpp>
#include <filesystem>
#include <future>
#include <io/netmp.hpp>
#include <nlohmann/json.hpp>
#include <string>

#include "utils.hpp"

using json = nlohmann::json;
namespace bpo = boost::program_options;
namespace fs = std::filesystem;

json commRunner(uint32_t num_parties, io::NetIOMP &net, ThreadPool &tpool,
                json &comm_data, uint32_t repeat) {
  emp::PRG prg;
  std::vector<std::vector<uint8_t>> send_bufs(num_parties);
  std::vector<std::vector<uint8_t>> recv_bufs(num_parties);

  auto rounds = comm_data["send"].size();

  json stats = json::array();

  std::cout << std::setprecision(3);

  for (auto r = 0; r < repeat; r++) {
    std::cout << "Reptition " << r + 1 << std::endl;
    std::cout << std::setw(6) << "Round" << std::setw(15) << "Time\t"
              << std::setw(20) << "Sent\t" << std::setw(20) << "Received"
              << std::endl;

    double total_time = 0;
    uint64_t total_sent = 0;
    uint64_t total_recv = 0;

    json rstats = json::array();

    for (auto i = 0; i < rounds; i++) {
      uint64_t rsent = 0;
      uint64_t rrecv = 0;

      for (auto p = 0; p < num_parties; p++) {
        auto psend = (static_cast<uint64_t>(comm_data["send"][i][p]) + 7) / 8;
        auto precv =
            (static_cast<uint64_t>(comm_data["receive"][i][p]) + 7) / 8;

        send_bufs[p].resize(psend);
        recv_bufs[p].resize(precv);
        if (!send_bufs[p].empty()) {
          prg.random_data(send_bufs[p].data(),
                          static_cast<int>(send_bufs[p].size()));
        }

        rsent += send_bufs[p].size();
        rrecv += recv_bufs[p].size();
      }

      std::vector<std::future<void>> fcomm;

      // Sync before communication to get accurate times for communication per
      // round.
      net.sync();

      TimePoint start;
      for (auto p = 0; p < num_parties; p++) {
        if (!send_bufs[p].empty()) {
          fcomm.push_back(tpool.enqueue([&, p]() {
            net.send(p, send_bufs[p].data(), send_bufs[p].size());
            net.flush(p);
          }));
        }

        if (!recv_bufs[p].empty()) {
          fcomm.push_back(tpool.enqueue([&, p]() {
            net.recv(p, recv_bufs[p].data(), recv_bufs[p].size());
          }));
        }
      }

      for (auto &f : fcomm) {
        f.get();
      }
      TimePoint end;

      auto rtime = end - start;
      rstats.push_back(rtime);
      total_time += rtime;
      total_sent += rsent;
      total_recv += rrecv;

      std::cout << std::setw(6) << i << std::setw(15) << rtime << " ms"
                << std::setw(20) << rsent << " B" << std::setw(20) << rrecv
                << " B" << std::endl;
    }
    std::cout << std::setw(6) << "Total" << std::setw(15) << total_time << " ms"
              << std::setw(20) << total_sent << " B" << std::setw(20)
              << total_recv << " B\n"
              << std::endl;
    stats.push_back(rstats);
  }

  return stats;
}

// clang-format off
bpo::options_description programOptions() {
  bpo::options_description desc("Emulate communication using computed statistics.");
  desc.add_options()
    ("party", bpo::value<uint32_t>()->required(), "ID of party (starts from 0)")
    ("input", bpo::value<std::string>()->required(), "Directory containing communication statistics.")
    ("output", bpo::value<std::string>(), "Directory to save benchmarks.")
    ("threads", bpo::value<uint32_t>()->default_value(1), "Number of threads.")
    ("port", bpo::value<uint16_t>()->default_value(9000), "Base port.")
    ("repeat", bpo::value<uint32_t>()->default_value(10), "Number of times to run benchmarks.");

  return desc;
}
// clang-format on

int main(int argc, char *argv[]) {
  auto prog_opts = programOptions();
  prog_opts.add_options()("help,h", "Produce help message.");

  bpo::variables_map opts;
  bpo::store(bpo::command_line_parser(argc, argv).options(prog_opts).run(),
             opts);

  if (opts.count("help") != 0) {
    std::cout << prog_opts << std::endl;
    return 0;
  }

  try {
    bpo::notify(opts);

    auto pid = opts["party"].as<uint32_t>();
    auto input_dir = fs::path(opts["input"].as<std::string>());
    auto threads = opts["threads"].as<uint32_t>();
    auto repeat = opts["repeat"].as<uint32_t>();
    auto port = opts["port"].as<uint16_t>();

    auto input_path =
        input_dir / fs::path((boost::format("party_%1%.json") % pid).str());

    std::ifstream fin;
    fin.open(input_path);
    if (!fin.is_open()) {
      throw std::runtime_error("Error opening input file.");
    }
    json comm_data;
    fin >> comm_data;

    auto num_parties = comm_data["send"][0].size();
    if (num_parties == 0) {
      throw std::runtime_error("Number of parties cannot be 0.");
    }

    io::NetIOMP net(static_cast<int32_t>(num_parties),
                    static_cast<int32_t>(pid), port, nullptr, true);
    ThreadPool tpool(threads);

    auto stats = commRunner(num_parties, net, tpool, comm_data, repeat);

    if (opts.count("output") != 0) {
      auto output_dir = fs::path(opts["output"].as<std::string>());
      auto output_path =
          output_dir / fs::path((boost::format("party_%1%.json") % pid).str());
      std::ofstream fout;
      fout.open(output_path);
      if (!fout.is_open()) {
        throw std::runtime_error("Error opening output file.");
      }
      fout << stats;
      std::cout << "Saved output in " << output_path << std::endl;
    }
  } catch (const std::exception &ex) {
    std::cerr << ex.what() << std::endl;
    return 1;
  }
}
