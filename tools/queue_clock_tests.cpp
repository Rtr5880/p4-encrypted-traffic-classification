// Standalone bounded regression checks for the real BMv2 queue templates.
// Compile with the directory containing the staged queueing.h on the include
// path; pass that exact header path to the executable for the source contract.
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "queueing.h"

namespace {
using Clock = std::chrono::steady_clock;
using Milliseconds = std::chrono::milliseconds;
static_assert(Clock::is_steady, "The test timing reference must be monotonic");

struct Mapper {
  std::size_t workers;
  std::size_t operator()(std::size_t queue_id) const {
    return queue_id % workers;
  }
};

using RL = bm::QueueingLogicRL<int, Mapper>;
using PriRL = bm::QueueingLogicPriRL<int, Mapper>;

void require(bool condition, const std::string &message) {
  if (!condition) throw std::runtime_error(message);
}

double elapsed_ms(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

// A bad blocking pop cannot leave this test process running indefinitely.
// No detached thread, external clock change, or interface access is used.
class Deadline {
 public:
  explicit Deadline(const std::string &name)
      : timer([this, name] {
          std::unique_lock<std::mutex> lock(mutex);
          if (!finished.wait_for(lock, Milliseconds(1500),
                                 [this] { return done; })) {
            std::cerr << "FAIL " << name << ": exceeded 1500 ms bound\n";
            std::_Exit(2);
          }
        }) {}

  ~Deadline() {
    {
      std::lock_guard<std::mutex> lock(mutex);
      done = true;
    }
    finished.notify_one();
    timer.join();
  }

 private:
  std::mutex mutex;
  std::condition_variable finished;
  bool done = false;
  std::thread timer;
};

void run(const std::string &name, const std::function<void()> &test) {
  Deadline deadline(name);
  const auto start = Clock::now();
  test();
  require(elapsed_ms(start) < 1200.0, name + ": unexpectedly slow");
  std::cout << "PASS " << name << " (" << elapsed_ms(start) << " ms)\n";
}

std::string active_source(const std::string &source) {
  std::istringstream lines(source);
  std::ostringstream result;
  std::string line;
  while (std::getline(lines, line)) {
    const auto comment = line.find("//");
    if (comment != std::string::npos) line.erase(comment);
    result << line << '\n';
  }
  return result.str();
}

void source_contract(const char *path) {
  std::ifstream input(path);
  require(static_cast<bool>(input), "cannot read supplied queueing.h");
  std::ostringstream contents;
  contents << input.rdbuf();
  const auto source = active_source(contents.str());
  const std::regex steady_alias(
      "using\\s+clock\\s*=\\s*std::chrono::steady_clock\\s*;");
  const std::regex steady_assert(
      "static_assert\\s*\\(\\s*clock::is_steady\\s*,");
  const std::regex nonsteady_alias(
      "using\\s+clock\\s*=\\s*std::chrono::high_resolution_clock\\s*;");
  const std::vector<std::string> classes = {
      "class QueueingLogicRL {", "class QueueingLogicPriRL {"};
  for (std::size_t index = 0; index < classes.size(); ++index) {
    const auto begin = source.find(classes[index]);
    require(begin != std::string::npos, classes[index] + ": missing class");
    const auto end = index + 1 < classes.size()
                         ? source.find(classes[index + 1], begin)
                         : source.size();
    const auto section = source.substr(begin, end - begin);
    require(std::regex_search(section, steady_alias),
            classes[index] + ": missing steady clock alias");
    require(std::regex_search(section, steady_assert),
            classes[index] + ": missing clock::is_steady assertion");
    require(!std::regex_search(section, nonsteady_alias),
            classes[index] + ": active high_resolution_clock alias remains");
  }
}

void rl_unlimited_fifo() {
  RL queue(1, 512, Mapper{1});
  for (int value = 0; value < 512; ++value) {
    const std::size_t queue_id = (value % 2 == 0) ? 11 : 23;
    require(queue.push_front(queue_id, value) == 1, "FIFO enqueue failed");
  }
  require(queue.size(11) == 256 && queue.size(23) == 256,
          "logical queue occupancies incorrect");
  for (int expected = 0; expected < 512; ++expected) {
    std::size_t queue_id = 0;
    int value = -1;
    queue.pop_back(0, &queue_id, &value);
    require(value == expected, "unlimited worker FIFO order changed");
    require(queue_id == ((expected % 2 == 0) ? 11u : 23u),
            "FIFO queue id changed");
  }
  require(queue.size(11) == 0 && queue.size(23) == 0,
          "FIFO queues did not drain");
}

void rl_zero_pps() {
  RL queue(1, 8, Mapper{1});
  queue.set_rate_for_all(0);
  queue.set_rate(42, 0);
  const auto start = Clock::now();
  for (int value = 0; value < 8; ++value) {
    require(queue.push_front(42, value) == 1, "0 pps enqueue failed");
  }
  for (int expected = 0; expected < 8; ++expected) {
    std::size_t queue_id = 0;
    int value = -1;
    queue.pop_back(0, &queue_id, &value);
    require(queue_id == 42 && value == expected, "0 pps FIFO changed");
  }
  require(elapsed_ms(start) < 500.0, "0 pps introduced a rate delay");
}

void rl_positive_rate() {
  RL queue(1, 3, Mapper{1});
  const auto start = Clock::now();
  queue.set_rate(7, 20);  // One scheduled release per 50 ms.
  for (int value = 0; value < 3; ++value) {
    require(queue.push_front(7, value) == 1, "rate enqueue failed");
  }
  for (int expected = 0; expected < 3; ++expected) {
    std::size_t queue_id = 0;
    int value = -1;
    queue.pop_back(0, &queue_id, &value);
    require(queue_id == 7 && value == expected, "rate FIFO changed");
    require(elapsed_ms(start) >= 50.0 * (expected + 1) - 5.0,
            "positive-rate item released before its deadline");
  }
  require(queue.size(7) == 0, "rate queue did not drain");
}

void rl_independent_queues() {
  RL queue(1, 2, Mapper{1});
  const auto start = Clock::now();
  queue.set_rate(5, 10);
  require(queue.push_front(5, 50) == 1, "slow queue enqueue failed");
  require(queue.push_front(8, 80) == 1, "unlimited queue enqueue failed");
  std::size_t queue_id = 0;
  int value = -1;
  queue.pop_back(0, &queue_id, &value);
  require(queue_id == 8 && value == 80,
          "slow queue delayed another logical queue");
  queue.pop_back(0, &queue_id, &value);
  require(queue_id == 5 && value == 50, "slow queue item changed");
  require(elapsed_ms(start) >= 95.0, "slow queue lost its rate limit");
}

void rl_worker_mapping() {
  RL queue(2, 2, Mapper{2});
  require(queue.push_front(10, 100) == 1, "worker 0 enqueue failed");
  require(queue.push_front(11, 110) == 1, "worker 1 enqueue failed");
  std::size_t queue_id = 0;
  int value = -1;
  queue.pop_back(1, &queue_id, &value);
  require(queue_id == 11 && value == 110, "worker 1 mapping changed");
  queue.pop_back(0, &queue_id, &value);
  require(queue_id == 10 && value == 100, "worker 0 mapping changed");
}

void rl_full_return() {
  bm::QueueingLogicRL<std::unique_ptr<int>, Mapper> queue(1, 1, Mapper{1});
  std::unique_ptr<int> accepted(new int(10));
  std::unique_ptr<int> rejected(new int(11));
  require(queue.push_front(4, std::move(accepted)) == 1 && !accepted,
          "accepted move enqueue failed");
  require(queue.push_front(4, std::move(rejected)) == 0,
          "full queue did not return zero");
  require(rejected && *rejected == 11, "full queue consumed rejected item");
  require(queue.size(4) == 1, "rejected item changed occupancy");
  std::unique_ptr<int> other(new int(20));
  require(queue.push_front(6, std::move(other)) == 1,
          "full queue affected another logical queue's capacity");
  std::size_t queue_id = 0;
  std::unique_ptr<int> value;
  queue.pop_back(0, &queue_id, &value);
  require(queue_id == 4 && value && *value == 10, "first moved item changed");
  require(queue.push_front(4, std::move(rejected)) == 1 && !rejected,
          "capacity did not become available after pop");
  queue.pop_back(0, &queue_id, &value);
  require(queue_id == 6 && value && *value == 20, "other queue item changed");
  queue.pop_back(0, &queue_id, &value);
  require(queue_id == 4 && value && *value == 11, "recovered item changed");
}

void pri_unlimited_fifo_and_priority() {
  PriRL queue(1, 128, Mapper{1}, 3);
  for (int value = 0; value < 64; ++value) {
    require(queue.push_front(17, 0, value) == 1, "low enqueue failed");
    require(queue.push_front(17, 2, 100 + value) == 1, "high enqueue failed");
  }
  require(queue.size(17) == 128 && queue.size(17, 2) == 64,
          "priority occupancies incorrect");
  for (int index = 0; index < 128; ++index) {
    std::size_t queue_id = 0;
    std::size_t priority = 99;
    int value = -1;
    queue.pop_back(0, &queue_id, &priority, &value);
    const bool high = index < 64;
    require(queue_id == 17 && priority == (high ? 2u : 0u),
            "priority selection changed");
    require(value == (high ? 100 + index : index - 64),
            "FIFO within a priority changed");
  }
  require(queue.size(17) == 0, "priority queues did not drain");
}

void pri_zero_pps() {
  PriRL queue(1, 4, Mapper{1}, 2);
  queue.set_rate_for_all(0);
  queue.set_rate(1, 1, 0);
  const auto start = Clock::now();
  for (int value = 0; value < 4; ++value) {
    require(queue.push_front(1, 1, value) == 1, "priority 0 pps enqueue failed");
  }
  for (int expected = 0; expected < 4; ++expected) {
    std::size_t queue_id = 0;
    std::size_t priority = 99;
    int value = -1;
    queue.pop_back(0, &queue_id, &priority, &value);
    require(queue_id == 1 && priority == 1 && value == expected,
            "priority 0 pps FIFO changed");
  }
  require(elapsed_ms(start) < 500.0, "priority 0 pps introduced a delay");
}

void pri_positive_rate() {
  PriRL queue(1, 3, Mapper{1}, 2);
  const auto start = Clock::now();
  queue.set_rate(7, 1, 20);
  for (int value = 0; value < 3; ++value) {
    require(queue.push_front(7, 1, value) == 1, "priority rate enqueue failed");
  }
  for (int expected = 0; expected < 3; ++expected) {
    std::size_t queue_id = 0;
    std::size_t priority = 99;
    int value = -1;
    queue.pop_back(0, &queue_id, &priority, &value);
    require(queue_id == 7 && priority == 1 && value == expected,
            "priority rate FIFO changed");
    require(elapsed_ms(start) >= 50.0 * (expected + 1) - 5.0,
            "priority rate item released before its deadline");
  }
  require(queue.size(7) == 0, "priority rate queue did not drain");
}

void pri_independent_priorities() {
  PriRL queue(1, 2, Mapper{1}, 2);
  const auto start = Clock::now();
  queue.set_rate(5, 1, 10);
  require(queue.push_front(5, 1, 51) == 1, "slow high enqueue failed");
  require(queue.push_front(5, 0, 50) == 1, "unlimited low enqueue failed");
  std::size_t queue_id = 0;
  std::size_t priority = 99;
  int value = -1;
  queue.pop_back(0, &queue_id, &priority, &value);
  require(queue_id == 5 && priority == 0 && value == 50,
          "ineligible high priority delayed eligible low priority");
  queue.pop_back(0, &queue_id, &priority, &value);
  require(queue_id == 5 && priority == 1 && value == 51,
          "slow high priority item changed");
  require(elapsed_ms(start) >= 95.0, "high priority lost its rate limit");
}

void pri_independent_queues() {
  PriRL queue(1, 2, Mapper{1}, 2);
  const auto start = Clock::now();
  queue.set_rate(5, 1, 10);
  require(queue.push_front(5, 1, 51) == 1, "slow priority queue enqueue failed");
  require(queue.push_front(8, 1, 81) == 1, "other priority queue enqueue failed");
  std::size_t queue_id = 0;
  std::size_t priority = 99;
  int value = -1;
  queue.pop_back(0, &queue_id, &priority, &value);
  require(queue_id == 8 && priority == 1 && value == 81,
          "rate leaked across logical queues in the same priority");
  queue.pop_back(0, &queue_id, &priority, &value);
  require(queue_id == 5 && priority == 1 && value == 51,
          "slow logical priority queue item changed");
  require(elapsed_ms(start) >= 95.0, "logical priority queue lost its rate");
}

void pri_worker_mapping() {
  PriRL queue(2, 2, Mapper{2}, 2);
  require(queue.push_front(10, 0, 100) == 1, "priority worker 0 enqueue failed");
  require(queue.push_front(11, 1, 111) == 1, "priority worker 1 enqueue failed");
  std::size_t queue_id = 0;
  std::size_t priority = 99;
  int value = -1;
  queue.pop_back(1, &queue_id, &priority, &value);
  require(queue_id == 11 && priority == 1 && value == 111,
          "priority worker 1 mapping changed");
  queue.pop_back(0, &queue_id, &priority, &value);
  require(queue_id == 10 && priority == 0 && value == 100,
          "priority worker 0 mapping changed");
}

void pri_full_return() {
  bm::QueueingLogicPriRL<std::unique_ptr<int>, Mapper> queue(
      1, 1, Mapper{1}, 2);
  std::unique_ptr<int> accepted(new int(11));
  std::unique_ptr<int> rejected(new int(12));
  require(queue.push_front(4, 1, std::move(accepted)) == 1 && !accepted,
          "accepted priority move enqueue failed");
  require(queue.push_front(4, 1, std::move(rejected)) == 0,
          "full priority queue did not return zero");
  require(rejected && *rejected == 12,
          "full priority queue consumed rejected item");
  std::unique_ptr<int> low(new int(10));
  require(queue.push_front(4, 0, std::move(low)) == 1,
          "full priority affected another priority's capacity");
  std::unique_ptr<int> other(new int(21));
  require(queue.push_front(6, 1, std::move(other)) == 1,
          "full priority affected another logical queue's capacity");
  require(queue.size(4) == 2 && queue.size(4, 1) == 1,
          "priority rejection changed occupancy");
  std::size_t queue_id = 0;
  std::size_t priority = 99;
  std::unique_ptr<int> value;
  queue.pop_back(0, &queue_id, &priority, &value);
  require(queue_id == 4 && priority == 1 && value && *value == 11,
          "first moved priority item changed");
  require(queue.push_front(4, 1, std::move(rejected)) == 1 && !rejected,
          "priority capacity unavailable after pop");
  queue.pop_back(0, &queue_id, &priority, &value);
  require(queue_id == 6 && priority == 1 && value && *value == 21,
          "other logical priority queue item changed");
  queue.pop_back(0, &queue_id, &priority, &value);
  require(queue_id == 4 && priority == 1 && value && *value == 12,
          "recovered priority item changed");
  queue.pop_back(0, &queue_id, &priority, &value);
  require(queue_id == 4 && priority == 0 && value && *value == 10,
          "lower priority item changed");
  require(queue.size(4) == 0 && queue.size(6) == 0,
          "capacity test priority queues did not drain");
}
}  // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "Usage: queue_clock_tests /absolute/path/to/staged/queueing.h\n";
    return 64;
  }
  try {
    run("source_contract_both_scheduled_clocks", [&] { source_contract(argv[1]); });
    run("RL_unlimited_FIFO", rl_unlimited_fifo);
    run("RL_0pps_unlimited", rl_zero_pps);
    run("RL_positive_rate_deadlines", rl_positive_rate);
    run("RL_independent_logical_queues", rl_independent_queues);
    run("RL_independent_workers", rl_worker_mapping);
    run("RL_full_return_and_move_preservation", rl_full_return);
    run("PriRL_priority_order_and_FIFO", pri_unlimited_fifo_and_priority);
    run("PriRL_0pps_unlimited", pri_zero_pps);
    run("PriRL_positive_rate_deadlines", pri_positive_rate);
    run("PriRL_independent_priorities", pri_independent_priorities);
    run("PriRL_independent_logical_queues", pri_independent_queues);
    run("PriRL_independent_workers", pri_worker_mapping);
    run("PriRL_full_return_and_move_preservation", pri_full_return);
    std::cout << "PASS all 14 bounded checks; no clock or network mutation\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "FAIL " << error.what() << '\n';
    return 1;
  }
}
