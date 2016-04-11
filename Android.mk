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


# Common variables.
# =========================================================
libminijailSrcFiles := \
	bpf.c \
	libminijail.c \
	signal_handler.c \
	syscall_filter.c \
	util.c

minijailCommonCFlags := -DHAVE_SECUREBITS_H -Wall -Werror
minijailCommonLibraries := libcap

# Android devices running kernel version < 3.8 are not required to
# support seccomp. Brillo devices must support seccomp regardless of
# kernel version.
# TODO: remove when no longer supporting kernel versions < 3.8.
ifndef BRILLO
minijailCommonCFlags += -DUSE_SECCOMP_SOFTFAIL
endif


# Static library for generated code.
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libminijail_generated

LOCAL_MODULE_CLASS := STATIC_LIBRARIES
generated_sources_dir := $(local-generated-sources-dir)

my_gen := $(generated_sources_dir)/$(TARGET_ARCH)/libsyscalls.c
# We need the quotes so the shell script treats the following as one argument.
my_cc := "$(lastword $(CLANG)) \
    $(addprefix -isystem ,$(TARGET_C_INCLUDES)) \
    $(CLANG_TARGET_GLOBAL_CFLAGS)"
$(my_gen): PRIVATE_CC := $(my_cc)
$(my_gen): PRIVATE_CUSTOM_TOOL = $< $(PRIVATE_CC) $@
$(my_gen): $(LOCAL_PATH)/gen_syscalls.sh
	$(transform-generated-source)
LOCAL_GENERATED_SOURCES_$(TARGET_ARCH) += $(my_gen)

my_gen := $(generated_sources_dir)/$(TARGET_ARCH)/libconstants.c
$(my_gen): PRIVATE_CC := $(my_cc)
$(my_gen): PRIVATE_CUSTOM_TOOL = $< $(PRIVATE_CC) $@
$(my_gen): $(LOCAL_PATH)/gen_constants.sh
	$(transform-generated-source)
LOCAL_GENERATED_SOURCES_$(TARGET_ARCH) += $(my_gen)

# For processes running in 32-bit compat mode on 64-bit processors.
ifdef TARGET_2ND_ARCH
my_gen := $(generated_sources_dir)/$(TARGET_2ND_ARCH)/libsyscalls.c
my_cc := "$(lastword $(CLANG)) \
    $(addprefix -isystem ,$($(TARGET_2ND_ARCH_VAR_PREFIX)TARGET_C_INCLUDES)) \
    $($(TARGET_2ND_ARCH_VAR_PREFIX)CLANG_TARGET_GLOBAL_CFLAGS)"
$(my_gen): PRIVATE_CC := $(my_cc)
$(my_gen): PRIVATE_CUSTOM_TOOL = $< $(PRIVATE_CC) $@
$(my_gen): $(LOCAL_PATH)/gen_syscalls.sh
	$(transform-generated-source)
LOCAL_GENERATED_SOURCES_$(TARGET_2ND_ARCH) += $(my_gen)

my_gen := $(generated_sources_dir)/$(TARGET_2ND_ARCH)/libconstants.c
$(my_gen): PRIVATE_CC := $(my_cc)
$(my_gen): PRIVATE_CUSTOM_TOOL = $< $(PRIVATE_CC) $@
$(my_gen): $(LOCAL_PATH)/gen_constants.sh
	$(transform-generated-source)
LOCAL_GENERATED_SOURCES_$(TARGET_2ND_ARCH) += $(my_gen)
endif

LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
include $(BUILD_STATIC_LIBRARY)


# libminijail shared library for target.
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libminijail

LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
LOCAL_SRC_FILES := $(libminijailSrcFiles)

LOCAL_STATIC_LIBRARIES := libminijail_generated
LOCAL_SHARED_LIBRARIES := $(minijailCommonLibraries)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
include $(BUILD_SHARED_LIBRARY)


# Example ASan-ified libminijail shared library for target.
# Commented out since it's only needed for local debugging.
# =========================================================
# include $(CLEAR_VARS)
# LOCAL_MODULE := libminijail_asan
# LOCAL_MODULE_TAGS := optional
#
# LOCAL_CFLAGS := $(minijailCommonCFlags)
# LOCAL_CLANG := true
# LOCAL_SANITIZE := address
# LOCAL_MODULE_RELATIVE_PATH := asan
# LOCAL_SRC_FILES := $(libminijailSrcFiles)
#
# LOCAL_STATIC_LIBRARIES := libminijail_generated
# LOCAL_SHARED_LIBRARIES := $(minijailCommonLibraries)
# LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
# include $(BUILD_SHARED_LIBRARY)


# libminijail static library for target.
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libminijail

LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
LOCAL_SRC_FILES := $(libminijailSrcFiles)

LOCAL_WHOLE_STATIC_LIBRARIES := libminijail_generated $(minijailCommonLibraries)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)


# libminijail native unit tests. Run with:
# adb shell /data/nativetest/libminijail_unittest/libminijail_unittest
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libminijail_unittest
ifdef BRILLO
  LOCAL_MODULE_TAGS := eng
endif

LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
LOCAL_SRC_FILES := \
	bpf.c \
	libminijail.c \
	libminijail_unittest.c \
	signal_handler.c \
	syscall_filter.c \
	util.c \

LOCAL_STATIC_LIBRARIES := libminijail_generated
LOCAL_SHARED_LIBRARIES := $(minijailCommonLibraries)
include $(BUILD_NATIVE_TEST)


# Syscall filtering native unit tests. Run with:
# adb shell /data/nativetest/syscall_filter_unittest/syscall_filter_unittest
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := syscall_filter_unittest
ifdef BRILLO
  LOCAL_MODULE_TAGS := eng
endif

LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
LOCAL_SRC_FILES := \
	bpf.c \
	syscall_filter.c \
	syscall_filter_unittest.c \
	util.c \

LOCAL_STATIC_LIBRARIES := libminijail_generated
LOCAL_SHARED_LIBRARIES := $(minijailCommonLibraries)
include $(BUILD_NATIVE_TEST)


# test_minijail executable for brillo_Minijail test.
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libminijail_test
ifdef BRILLO
  LOCAL_MODULE_TAGS := eng
endif

LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
LOCAL_SRC_FILES := \
	test/libminijail_test.cpp

LOCAL_SHARED_LIBRARIES := libbase libminijail
include $(BUILD_EXECUTABLE)


# libminijail usage example.
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := drop_privs
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
# Don't build with ASan, but leave commented out for easy local debugging.
# LOCAL_SANITIZE := address
LOCAL_SRC_FILES := \
	examples/drop_privs.cpp

LOCAL_SHARED_LIBRARIES := libbase libminijail
include $(BUILD_EXECUTABLE)


# minijail0 executable.
# This is not currently used on Brillo/Android,
# but it's convenient to be able to build it.
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := minijail0
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := \
	$(minijailCommonCFlags) -Wno-missing-field-initializers \
	-DPRELOADPATH=\"/invalidminijailpreload.so\"
LOCAL_CLANG := true
LOCAL_SRC_FILES := \
	elfparse.c \
	minijail0.c \

LOCAL_STATIC_LIBRARIES := libminijail_generated
LOCAL_SHARED_LIBRARIES := $(minijailCommonLibraries) libminijail
include $(BUILD_EXECUTABLE)
