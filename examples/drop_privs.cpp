// Copyright (C) 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <sys/types.h>
#include <sys/capability.h>
#include <unistd.h>

#include <libminijail.h>

#include <android-base/logging.h>
#include <android-base/macros.h>

gid_t groups[] = { 1001, 1002 };

void log_resugid() {
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    getresuid(&ruid, &euid, &suid);
    getresgid(&rgid, &egid, &sgid);

    LOG(INFO) << "ruid " << ruid << " euid " << euid << " suid " << suid;
    LOG(INFO) << "rgid " << rgid << " egid " << egid << " sgid " << sgid;

    int nsupp_groups = getgroups(0, NULL);
    if (nsupp_groups < 0) {
        PLOG(FATAL) << "getgroups(0)";
    }
    if (nsupp_groups == 0) {
        LOG(INFO) << "no supplemental groups";
        return;
    }

    gid_t *list = (gid_t*)calloc((size_t)nsupp_groups, sizeof(gid_t));
    nsupp_groups = getgroups(nsupp_groups, list);
    if (nsupp_groups < 0) {
        PLOG(FATAL) << "getgroups(nsupp_groups)";
    }
    for (size_t i = 0; i < (size_t)nsupp_groups; i++) {
        LOG(INFO) << "supp gid " << i + 1 << " " << list[i];
    }
    free(list);
}

int main(void) {
    log_resugid();
    minijail *j = minijail_new();
    minijail_change_user(j, "system");
    minijail_change_group(j, "system");
    minijail_set_supplementary_gids(j, arraysize(groups), groups);
    // minijail_use_caps(j, CAP_TO_MASK(CAP_SETUID) | CAP_TO_MASK(CAP_SETGID));
    // minijail_use_seccomp_filter(j);
    // minijail_log_seccomp_filter_failures(j);
    // minijail_parse_seccomp_filters(j, "/data/filter.policy");
    minijail_enter(j);
    log_resugid();
    minijail_destroy(j);
    // minijail *j2 = minijail_new();
    // minijail_change_uid(j2, 5000);
    // minijail_change_gid(j2, 5000);
    // minijail_enter(j2);
    // log_resugid();
    return 0;
}
