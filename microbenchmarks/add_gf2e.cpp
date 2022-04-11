#include <NTL/BasicThreadPool.h>
#include <NTL/GF2E.h>
#include <NTL/GF2XFactoring.h>
#include <NTL/ZZ.h>
#include <NTL/matrix.h>
#include <NTL/vec_GF2E.h>

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
  bpo::options_description desc("Benchmark additions over GF2E.");
  desc.add_options()
    ("field_degree,d", bpo::value<uint32_t>()->default_value(8), "Degree of the polynomial modulus of the extension field.")
    ("num,n", bpo::value<uint32_t>()->default_value(1000000), "Number of additions.")
    ("threads,t", bpo::value<uint32_t>()->default_value(1), "Number of threads.")
    ("seed", bpo::value<uint32_t>()->default_value(200), "Value of the random seed.")
    ("output,o", bpo::value<std::string>(), "File to save benchmarks.")
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
    auto threads = opts["threads"].as<uint32_t>();
    auto seed = opts["seed"].as<uint32_t>();
    auto repeat = opts["repeat"].as<uint32_t>();

    // Check if output file already exists
    bool save_output = false;
    fs::path output_path;
    if (opts.count("output") != 0) {
      fs::path output_dir(opts["output"].as<std::string>());
      fs::path filename =
          (boost::format("addgf2e_d%1%_t%2%.json") % field_degree % threads)
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
                              {"threads", threads},
                              {"seed", seed},
                              {"repeat", repeat}};

    NTL::SetNumThreads(threads);
    NTL::SetSeed(NTL::conv<NTL::ZZ>(seed));

    auto poly_mod = NTL::BuildSparseIrred_GF2X(field_degree);
    NTL::GF2E::init(poly_mod);

    NTL::Vec<NTL::GF2E> va;
    NTL::Vec<NTL::GF2E> vb;
    NTL::Vec<NTL::GF2E> vc;
    va.SetLength(num);
    vb.SetLength(num);
    vc.SetLength(num);

    output_data["stats"] = json::array();
    double total_time = 0;

    std::cout << std::setprecision(3) << std::scientific;

    for (size_t r = 0; r < repeat; r++) {
      NTL::random(va, num);
      NTL::random(vb, num);

      TimePoint start;
      NTL_EXEC_RANGE(num, first, last)
      NTL::GF2E::init(poly_mod);
      for (long i = first; i < last; ++i) {
        vc[i] = va[i] + vb[i];
      }
      NTL_EXEC_RANGE_END
      TimePoint end;

      auto ctime = end - start;
      output_data["stats"].push_back(ctime);
      total_time += ctime;

      auto ctime_add = ctime / num;
      std::cout << "Repetition " << (r + 1) << ":\t" << ctime << " ms\t"
                << ctime_add << " ms/addition" << std::endl;
    }

    std::cout << "\nAverage time:\t" << total_time / repeat << " ms\t"
              << total_time / (repeat * num) << " ms/addition" << std::endl;

    if (save_output) {
      saveJson(output_data, output_path);
    }
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << std::endl;
    return 1;
  }
}
