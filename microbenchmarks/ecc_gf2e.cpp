#include <NTL/BasicThreadPool.h>
#include <NTL/GF2E.h>
#include <NTL/GF2XFactoring.h>
#include <NTL/ZZ.h>
#include <NTL/mat_GF2E.h>
#include <NTL/matrix.h>

#include <boost/format.hpp>
#include <boost/program_options.hpp>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>

#include "utils.hpp"

using json = nlohmann::json;
namespace bpo = boost::program_options;
namespace fs = std::filesystem;

// clang-format off
bpo::options_description programOptions() {
  bpo::options_description desc("Benchmark ECC over GF2E.");
  desc.add_options()
    ("field_degree,d", bpo::value<uint32_t>()->default_value(8), "Degree of the polynomial modulus of the extension field.")
    ("num", bpo::value<uint32_t>()->default_value(100), "Number of messages to encode.")
    ("mssg_len", bpo::value<uint32_t>()->default_value(1276), "Number of GF2E elements for each message.")
    ("code_len", bpo::value<uint32_t>()->default_value(3600), "Number of GF2E elements in final codeword")
    ("threads,t", bpo::value<uint32_t>()->default_value(1), "Number of threads.")
    ("seed", bpo::value<uint32_t>()->default_value(200), "Value of the random seed.")
    ("output,o", bpo::value<std::string>(), "Directory to save benchmarks.")
    ("repeat,r", bpo::value<uint32_t>()->default_value(10), "Number of times to run benchmarks.");

  return desc;
}
// clang-format on

int main(int argc, char* argv[]) {
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

    auto field_degree = opts["field_degree"].as<uint32_t>();
    uint32_t num = opts["num"].as<uint32_t>();
    uint32_t mssg_len = opts["mssg_len"].as<uint32_t>();
    uint32_t code_len = opts["code_len"].as<uint32_t>();
    auto threads = opts["threads"].as<uint32_t>();
    auto seed = opts["seed"].as<uint32_t>();
    auto repeat = opts["repeat"].as<uint32_t>();

    // Check if output file already exists
    bool save_output = false;
    fs::path output_path;
    if (opts.count("output") != 0) {
      fs::path output_dir(opts["output"].as<std::string>());
      fs::path filename = (boost::format("ecc_d%1%_m%2%_c%3%_t%4%.json") %
                           field_degree % mssg_len % code_len % threads)
                              .str();
      output_path = output_dir / filename;

      std::ifstream ftemp(output_path);
      if (ftemp.good()) {
        ftemp.close();
        throw std::runtime_error("Output file aready exists.");
      }
      ftemp.close();
      save_output = true;
    }

    json output_data;
    output_data["details"] = {{"field_degree", field_degree},
                              {"num", num},
                              {"mssg_len", mssg_len},
                              {"code_len", code_len},
                              {"threads", threads},
                              {"seed", seed},
                              {"repeat", repeat}};

    NTL::SetNumThreads(threads);
    NTL::SetSeed(NTL::conv<NTL::ZZ>(seed));

    auto poly_mod = NTL::BuildSparseIrred_GF2X(field_degree);
    NTL::GF2E::init(poly_mod);

    NTL::Mat<NTL::GF2E> generator;
    NTL::Mat<NTL::GF2E> mssgs;
    generator.SetDims(code_len, mssg_len);
    mssgs.SetDims(mssg_len, num);

    output_data["stats"] = json::array();
    double total_time = 0;

    std::cout << std::setprecision(3) << std::scientific;

    for (size_t r = 0; r < repeat; r++) {
      NTL::random(generator, code_len, mssg_len);
      NTL::random(mssgs, mssg_len, num);

      TimePoint start;
      auto codes = generator * mssgs;
      TimePoint end;

      auto ctime = end - start;
      output_data["stats"].push_back(ctime);

      auto ctime_enc = ctime / num;
      std::cout << "Repetition " << (r + 1) << ":\t" << ctime << " ms \t"
                << ctime_enc << " ms/message" << std::endl;
      total_time += ctime;
    }

    std::cout << "\nAverage time:\t" << total_time / repeat << " ms \t"
              << total_time / (repeat * num) << " ms/message" << std::endl;

    if (save_output) {
      saveJson(output_data, output_path);
    }
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << std::endl;
    return 1;
  }
}
