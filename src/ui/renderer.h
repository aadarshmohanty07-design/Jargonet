#pragma once

#include <atomic>
#include <iosfwd>
#include <mutex>
#include <string>

#include "ui/events.h"

namespace jn::ui {

bool stdout_supports_color();
int terminal_width();

class IRenderer {
 public:
  virtual ~IRenderer() = default;

  virtual void emit(const UIEvent& event) = 0;
  virtual void clear() = 0;
  virtual void show_prompt() = 0;
  virtual void flush() = 0;
  virtual void set_show_route(bool enabled) { (void)enabled; }
  virtual void set_full_hex(bool enabled) { (void)enabled; }
};

class Renderer final : public IRenderer {
 public:
  Renderer(std::ostream& out, bool color, int width = 0);

  void emit(const UIEvent& event) override;
  void clear() override;
  void show_prompt() override;
  void flush() override;
  void set_show_route(bool enabled) override;
  void set_full_hex(bool enabled) override;

  bool show_route() const;
  bool full_hex() const;

 private:
  std::string format(const UIEvent& event) const;

  std::ostream& out_;
  bool color_;
  int width_ = 0;
  mutable std::mutex out_mutex_;
  std::atomic<bool> show_route_{true};
  std::atomic<bool> full_hex_{false};
};

// Headless sink for backend tests. Only relay hops and errors reach stderr.
class NullUI final : public IRenderer {
 public:
  NullUI();

  void emit(const UIEvent& event) override;
  void clear() override {}
  void show_prompt() override {}
  void flush() override;

 private:
  Renderer sink_;
};

}  // namespace jn::ui
