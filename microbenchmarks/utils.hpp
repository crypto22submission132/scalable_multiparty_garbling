#include <chrono>
#include <nlohmann/json.hpp>
#include <string>

class TimePoint {
 public:
  using timepoint_t = std::chrono::high_resolution_clock::time_point;
  using timeunit_t = std::chrono::duration<double, std::milli>;

  TimePoint();
  double operator-(const TimePoint& rhs);

 private:
  timepoint_t time_;
};

bool saveJson(const nlohmann::json& data, const std::string& fpath);
