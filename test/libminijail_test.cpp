// Copyright (C) 2016 The Android Open Source Project
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

const uid_t kSystemUid = 1000U;

gid_t groups[] = { kSystemUid + 1, kSystemUid + 2 };

size_t getgroups_with_alloc(gid_t **plist) {
    *plist = NULL;

    int nsupp_groups = getgroups(0, NULL);
    if (nsupp_groups < 0) {
        PLOG(ERROR) << "getgroups(0)";
        return 0;
    }
    if (nsupp_groups == 0) {
        LOG(INFO) << "No supplementary groups.";
        return 0;
    }

    *plist = (gid_t*)calloc((size_t)nsupp_groups, sizeof(gid_t));
    nsupp_groups = getgroups(nsupp_groups, *plist);
    if (nsupp_groups < 0) {
        PLOG(ERROR) << "getgroups(nsupp_groups)";
        free(*plist);
        return 0;
    }
    return nsupp_groups;
}

bool check_ugid(uid_t expected_id) {
    bool success = true;

    uid_t ruid = getuid();
    if (ruid != expected_id) {
        LOG(ERROR) << "rUID " << ruid << " is not " << expected_id;
        success = false;
    }
    gid_t rgid = getgid();
    if (rgid != expected_id) {
        LOG(ERROR) << "rGID " << ruid << " is not " << expected_id;
        success = false;
    }
    return success;
}

bool check_groups(size_t expected_size, gid_t *expected_list) {
    bool success = true;

    gid_t *actual_list;
    size_t actual_size = getgroups_with_alloc(&actual_list);

    if (expected_size != actual_size) {
        LOG(ERROR) << "Mismatched supplementary group list size: expected "
                   << expected_size << ", actual " << actual_size;
        success = false;
    }

    for (size_t i = 0; i < expected_size; i++) {
        bool found = false;
        for (size_t j = 0; j < actual_size; j++) {
            if (expected_list[i] == actual_list[j]) {
                // Test next expected GID.
                found = true;
                break;
            }
        }
        if (!found) {
            LOG(ERROR) << "Expected GID " << expected_list[i] << " not found.";
            success = false;
        }
    }
    free(actual_list);
    return success;
}

void log_resugid() {
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    getresuid(&ruid, &euid, &suid);
    getresgid(&rgid, &egid, &sgid);

    LOG(INFO) << "ruid " << ruid << " euid " << euid << " suid " << suid;
    LOG(INFO) << "rgid " << rgid << " egid " << egid << " sgid " << sgid;

    gid_t *list;
    size_t nsupp_groups = getgroups_with_alloc(&list);
    for (size_t i = 0; i < (size_t)nsupp_groups; i++) {
        LOG(INFO) << "supp gid " << i + 1 << " " << list[i];
    }
    free(list);
}

int main(void) {
    minijail *j = minijail_new();
    minijail_change_user(j, "system");
    minijail_change_group(j, "system");
    size_t num_groups = sizeof(groups) / sizeof(groups[0]);
    minijail_set_supplementary_gids(j, num_groups, groups);
    minijail_use_caps(j, CAP_TO_MASK(CAP_SETUID) | CAP_TO_MASK(CAP_SETGID));
    minijail_enter(j);

    bool success = check_ugid(kSystemUid);
    success = success && check_groups(num_groups, groups);

    minijail_destroy(j);
    minijail *j2 = minijail_new();
    minijail_change_uid(j2, 5 * kSystemUid);
    minijail_change_gid(j2, 5 * kSystemUid);
    minijail_enter(j2);

    success = success && check_ugid(5 * kSystemUid);

    return success? 0 : 1;
}
