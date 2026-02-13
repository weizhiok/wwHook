TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FakeBundleID

FakeBundleID_FILES = Tweak.x
FakeBundleID_CFLAGS = -fobjc-arc

# 只链接这 3 个最基础的公开框架
FakeBundleID_FRAMEWORKS = UIKit Foundation CoreFoundation

include $(THEOS_MAKE_PATH)/tweak.mk
