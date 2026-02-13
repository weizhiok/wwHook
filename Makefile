TARGET := iphone:clang:latest:14.0
include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = FakeBundleID
FakeBundleID_FILES = Tweak.m
FakeBundleID_CFLAGS = -fobjc-arc
FakeBundleID_FRAMEWORKS = Foundation

# 必须是 library.mk，不能是 tweak.mk
include $(THEOS_MAKE_PATH)/library.mk
