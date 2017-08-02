/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef SRC_LOGGER_H_
#define SRC_LOGGER_H_

#include <PI/frontends/proto/logging.h>

#include <memory>
#include <string>

#include "fmt/format.h"

namespace pi {

namespace fe {

namespace proto {

class Logger {
 public:
  using Severity = LogWriterIface::Severity;

  static Logger *get() {
    static Logger logger;
    return &logger;
  }

  // setter methods are not thread-safe
  void set_writer(std::shared_ptr<LogWriterIface> writer) {
    this->writer = writer;
  }

  void set_min_severity(Severity min_severity) {
    this->min_severity = min_severity;
  }

  template <typename Arg1, typename... Args>
  void log(Severity severity, const char *fmt,
           const Arg1 &arg1, const Args &... args) {
    if (severity < min_severity) return;
    fmt::MemoryWriter buffer;
    buffer.write(fmt, arg1, args...);
    writer->write(severity, buffer.c_str());
  }

  void log(Severity severity, const char *msg) {
    if (severity < min_severity) return;
    writer->write(severity, msg);
  }

  void log(Severity severity, const std::string &msg) {
    if (severity < min_severity) return;
    writer->write(severity, msg.c_str());
  }

  // convenience logging functions

  template <typename... Args>
  void trace(const char *fmt, const Args &... args) {
    log(Severity::TRACE, fmt, args...);
  }
  void trace(const std::string &msg) {
    log(Severity::TRACE, msg);
  }

  template <typename... Args>
  void debug(const char *fmt, const Args &... args) {
    log(Severity::DEBUG, fmt, args...);
  }
  void debug(const std::string &msg) {
    log(Severity::DEBUG, msg);
  }

  template <typename... Args>
  void info(const char *fmt, const Args &... args) {
    log(Severity::INFO, fmt, args...);
  }
  void info(const std::string &msg) {
    log(Severity::INFO, msg);
  }

  template <typename... Args>
  void warn(const char *fmt, const Args &... args) {
    log(Severity::WARN, fmt, args...);
  }
  void warn(const std::string &msg) {
    log(Severity::WARN, msg);
  }

  template <typename... Args>
  void error(const char *fmt, const Args &... args) {
    log(Severity::ERROR, fmt, args...);
  }
  void error(const std::string &msg) {
    log(Severity::ERROR, msg);
  }

  template <typename... Args>
  void critical(const char *fmt, const Args &... args) {
    log(Severity::CRITICAL, fmt, args...);
  }
  void critical(const std::string &msg) {
    log(Severity::CRITICAL, msg);
  }

 private:
  Logger() : writer(std::make_shared<LogWriterIface>()) { }

  std::shared_ptr<LogWriterIface> writer{nullptr};
  Severity min_severity{Severity::TRACE};
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_LOGGER_H_
