TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FakeBundleID

FakeBundleID_FILES = Tweak.x
FakeBundleID_CFLAGS = -fobjc-arc
# 链接必要的系统框架
FakeBundleID_FRAMEWORKS = UIKit Foundation CoreFoundation
# 链接私有框架，用于支持 LSApplicationProxy
FakeBundleID_PRIVATE_FRAMEWORKS = MobileCoreServices

include $(THEOS_MAKE_PATH)/tweak.mk
