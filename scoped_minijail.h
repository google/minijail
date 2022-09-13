/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef _SCOPED_MINIJAIL_H_
#define _SCOPED_MINIJAIL_H_

#include <memory>

#include "libminijail.h"

namespace mj {

namespace internal {

struct ScopedMinijailDeleter {
    inline void operator()(minijail *j) const {
        if (j) {
            minijail_destroy(j);
        }
    }
};

}   // namespace internal

}   // namespace mj

using ScopedMinijail =
        std::unique_ptr<minijail, mj::internal::ScopedMinijailDeleter>;

#endif /* _SCOPED_MINIJAIL_H_ */
