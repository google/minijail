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
	syscall_wrapper.c \
	system.c \
	util.c

hostUnittestSrcFiles := \
	linux-x86/libconstants.gen.c \
	linux-x86/libsyscalls.gen.c

minijailCommonCFlags := -DHAVE_SECUREBITS_H -Wall -Werror
minijailCommonLibraries := libcap


# Static library for generated code.
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libminijail_generated
include $(LOCAL_PATH)/gen.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE:= libminijail_generated_vendor
include $(LOCAL_PATH)/gen.mk
LOCAL_VENDOR_MODULE := true
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

include $(CLEAR_VARS)
LOCAL_MODULE := libminijail_vendor

LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
LOCAL_SRC_FILES := $(libminijailSrcFiles)
LOCAL_VENDOR_MODULE := true

LOCAL_STATIC_LIBRARIES := libminijail_generated_vendor
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


# libminijail native unit tests using gtest. Run with:
# adb shell /data/nativetest/libminijail_unittest_gtest/libminijail_unittest_gtest
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libminijail_unittest_gtest
LOCAL_COMPATIBILITY_SUITE := device-tests

LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS := $(minijailCommonCFlags) -Wno-writable-strings
LOCAL_CLANG := true
LOCAL_SRC_FILES := \
	$(libminijailSrcFiles) \
	libminijail_unittest.cc \

LOCAL_STATIC_LIBRARIES := libminijail_generated
LOCAL_SHARED_LIBRARIES := $(minijailCommonLibraries)
include $(BUILD_NATIVE_TEST)


# # libminijail native unit tests for the host. Run with:
# # out/host/linux-x86/nativetest(64)/libminijail_unittest/libminijail_unittest_gtest
# # TODO(b/31395668): Re-enable once the seccomp(2) syscall becomes available.
# # =========================================================
# include $(CLEAR_VARS)
# LOCAL_MODULE := libminijail_unittest_gtest
# LOCAL_MODULE_HOST_OS := linux

# LOCAL_CPP_EXTENSION := .cc
# LOCAL_CFLAGS := $(minijailCommonCFlags) -DPRELOADPATH=\"/invalid\"
# LOCAL_CLANG := true
# LOCAL_SRC_FILES := \
# 	$(libminijailSrcFiles) \
# 	libminijail_unittest.cc \
# 	$(hostUnittestSrcFiles)

# LOCAL_SHARED_LIBRARIES := $(minijailCommonLibraries)
# include $(BUILD_HOST_NATIVE_TEST)


# Syscall filtering native unit tests using gtest. Run with:
# adb shell /data/nativetest/syscall_filter_unittest_gtest/syscall_filter_unittest_gtest
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := syscall_filter_unittest_gtest
LOCAL_COMPATIBILITY_SUITE := device-tests

LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
LOCAL_SRC_FILES := \
	bpf.c \
	syscall_filter.c \
	util.c \
	syscall_filter_unittest.cc \

LOCAL_STATIC_LIBRARIES := libminijail_generated
LOCAL_SHARED_LIBRARIES := $(minijailCommonLibraries)
include $(BUILD_NATIVE_TEST)


# Syscall filtering native unit tests for the host. Run with:
# out/host/linux-x86/nativetest(64)/syscall_filter_unittest_gtest/syscall_filter_unittest_gtest
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := syscall_filter_unittest_gtest
LOCAL_MODULE_HOST_OS := linux

LOCAL_CPP_EXTENSION := .cc
LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
LOCAL_SRC_FILES := \
	bpf.c \
	syscall_filter.c \
	util.c \
	syscall_filter_unittest.cc \
	$(hostUnittestSrcFiles)

LOCAL_SHARED_LIBRARIES := $(minijailCommonLibraries)
include $(BUILD_HOST_NATIVE_TEST)


# libminijail_test executable for brillo_Minijail test.
# =========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libminijail_test
LOCAL_COMPATIBILITY_SUITE := device-tests

LOCAL_CFLAGS := $(minijailCommonCFlags)
LOCAL_CLANG := true
LOCAL_GTEST := false
LOCAL_SRC_FILES := \
	test/libminijail_test.cpp

LOCAL_SHARED_LIBRARIES := libbase libminijail
include $(BUILD_NATIVE_TEST)


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
