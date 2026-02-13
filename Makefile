TARGET := iphone:clang:latest:14.0
# 移除 SpringBoard 限制，允许注入任何进程
# INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

# 注意：这里改成了 LIBRARY_NAME，不再是 TWEAK_NAME
LIBRARY_NAME = FakeBundleID

FakeBundleID_FILES = Tweak.m
FakeBundleID_CFLAGS = -fobjc-arc
FakeBundleID_FRAMEWORKS = UIKit Foundation

# 🟢 关键修改：使用 library.mk (普通库模式)，完全脱离 Substrate 依赖
include $(THEOS_MAKE_PATH)/library.mk
