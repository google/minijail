# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LOCAL_PATH := $(call my-dir)

# Common variables
# ========================================================

minijailCommonCFlags := -Wall -Werror -Wno-unused-function \
    -Wno-unused-parameter -Wno-sign-compare
minijailCommonSharedLibraries := libcap

# libminijail shared library for target
# ========================================================

include $(CLEAR_VARS)
LOCAL_MODULE := libminijail

# LOCAL_MODULE_CLASS must be defined before calling $(local-generated-sources-dir)
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
intermediates := $(local-generated-sources-dir)
GEN := $(intermediates)/libsyscalls.c
$(GEN): PRIVATE_CUSTOM_TOOL = $< "$(lastword $(CLANG)) -isystem bionic/libc/kernel/uapi/asm-$(TARGET_ARCH)" $@
$(GEN): $(LOCAL_PATH)/gen_syscalls.sh
	$(transform-generated-source)
LOCAL_GENERATED_SOURCES += $(GEN)

GEN := $(intermediates)/libconstants.c
$(GEN): PRIVATE_CUSTOM_TOOL = $< "$(lastword $(CLANG)) -isystem bionic/libc/kernel/uapi/asm-$(TARGET_ARCH)" $@
$(GEN): $(LOCAL_PATH)/gen_constants.sh
	$(transform-generated-source)
LOCAL_GENERATED_SOURCES += $(GEN)

LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
LOCAL_SRC_FILES := \
	bpf.c \
	libminijail.c \
	signal_handler.c \
	syscall_filter.c \
	util.c \

LOCAL_SHARED_LIBRARIES := $(minijailCommonSharedLibraries)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
include $(BUILD_SHARED_LIBRARY)
