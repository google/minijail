/* Copyright 2018 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

// Generate a .json file with all the architecture-specific constants.

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>

#include "arch.h"
#include "libconstants.h"
#include "libsyscalls.h"

int main() {
  std::cout << "{\n";
  std::cout << "  \"arch_nr\": " << ARCH_NR << ",\n";
  std::cout << "  \"arch_name\": \"" << ARCH_NAME << "\",\n";
  std::cout << "  \"bits\": " << (sizeof(uintptr_t) * 8) << ",\n";
  std::cout << "  \"syscalls\": {\n";
  bool first = true;
  for (const struct syscall_entry* entry = syscall_table; entry->name;
       ++entry) {
    if (first)
      first = false;
    else
      std::cout << ",\n";
    std::cout << "    \"" << entry->name << "\": " << entry->nr;
  }
  std::cout << "\n  },\n";
  std::cout << "  \"constants\": {\n";
  first = true;
  for (const struct constant_entry* entry = constant_table; entry->name;
       ++entry) {
    if (first)
      first = false;
    else
      std::cout << ",\n";
    std::cout << "    \"" << entry->name << "\": " << entry->value;
  }
  std::cout << "\n  }\n";
  std::cout << "}\n";

  return 0;
}
