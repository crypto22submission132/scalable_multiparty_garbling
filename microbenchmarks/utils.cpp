#include "utils.hpp"

#include <fstream>
#include <iostream>

TimePoint::TimePoint() : time_(timepoint_t::clock::now()) {}

double TimePoint::operator-(const TimePoint& rhs) {
  return std::chrono::duration_cast<timeunit_t>(time_ - rhs.time_).count();
}

bool saveJson(const nlohmann::json& data, const std::string& fpath) {
  std::ofstream fout;
  fout.open(fpath, std::fstream::out);
  if (!fout.is_open()) {
    std::cerr << "Could not open save file at " << fpath << "\n";
    return false;
  }

  fout << data;
  fout.close();

  std::cout << "Saved data in " << fpath << std::endl;

  return true;
}
