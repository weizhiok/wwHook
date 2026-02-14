TARGET := iphone:clang:latest:15.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = StealthBundleID
StealthBundleID_FILES = Tweak.m
StealthBundleID_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
StealthBundleID_FRAMEWORKS = Foundation Security

include $(THEOS_MAKE_PATH)/library.mk
