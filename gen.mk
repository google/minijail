LOCAL_MODULE_CLASS := STATIC_LIBRARIES
generated_sources_dir := $(local-generated-sources-dir)

my_gen := $(generated_sources_dir)/$(TARGET_ARCH)/libsyscalls.c
# We need the quotes so the shell script treats the following as one argument.
my_cc := "$(lastword $(CLANG)) \
    $(addprefix -I ,$(TARGET_C_INCLUDES)) \
    $(addprefix -isystem ,$(TARGET_C_SYSTEM_INCLUDES)) \
    $(CLANG_TARGET_GLOBAL_CFLAGS)"
$(my_gen): PRIVATE_CC := $(my_cc)
$(my_gen): PRIVATE_CUSTOM_TOOL = $< $(PRIVATE_CC) $@
$(my_gen): $(LOCAL_PATH)/gen_syscalls.sh
	$(transform-generated-source)
$(call include-depfile,$(my_gen).d,$(my_gen))
LOCAL_GENERATED_SOURCES_$(TARGET_ARCH) += $(my_gen)

my_gen := $(generated_sources_dir)/$(TARGET_ARCH)/libconstants.c
$(my_gen): PRIVATE_CC := $(my_cc)
$(my_gen): PRIVATE_CUSTOM_TOOL = $< $(PRIVATE_CC) $@
$(my_gen): $(LOCAL_PATH)/gen_constants.sh
	$(transform-generated-source)
$(call include-depfile,$(my_gen).d,$(my_gen))
LOCAL_GENERATED_SOURCES_$(TARGET_ARCH) += $(my_gen)

# For processes running in 32-bit compat mode on 64-bit processors.
ifdef TARGET_2ND_ARCH
my_gen := $(generated_sources_dir)/$(TARGET_2ND_ARCH)/libsyscalls.c
my_cc := "$(lastword $(CLANG)) \
    $(addprefix -I ,$($(TARGET_2ND_ARCH_VAR_PREFIX)TARGET_C_INCLUDES)) \
    $(addprefix -isystem ,$($(TARGET_2ND_ARCH_VAR_PREFIX)TARGET_C_SYSTEM_INCLUDES)) \
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
