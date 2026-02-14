#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h> // 用于震动
#import <objc/runtime.h>

// =======================================================
// ⚙️ 配置区域
// =======================================================
static NSString * const kTargetBundleID = @"com.user.bundlechecker";
// =======================================================

// ----------------------------------------------------------------
// 📢 1. 必杀技：构造函数 (加载即运行)
// ----------------------------------------------------------------
__attribute__((constructor)) static void ModuleEntry() {
    // 1. 先打印日志 (可以在控制台看到)
    NSLog(@"[DebugPlugin] 🔥 插件已由系统加载 (dlopen success)!");
    NSLog(@"[DebugPlugin] 🔥 准备执行注入逻辑...");

    // 2. 震动反馈 (物理验证)
    // 如果你感觉手机震了一下，说明插件 100% 加载了，即使没弹窗也是 UI 问题
    AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);

    // 3. 延时弹窗 (视觉验证)
    // 延迟 6 秒，给 App 一点时间去加载 UI，防止弹窗弹在空气里
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        NSLog(@"[DebugPlugin] ⏰ 正在尝试唤起弹窗...");
        
        // 寻找当前屏幕的主窗口
        UIWindow *topWindow = nil;
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                if (scene.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *w in scene.windows) {
                        if (w.isKeyWindow) {
                            topWindow = w;
                            break;
                        }
                    }
                }
            }
        }
        // 兜底方案
        if (!topWindow) {
            topWindow = [UIApplication sharedApplication].windows.firstObject;
        }

        if (topWindow) {
            UIViewController *rootVC = topWindow.rootViewController;
            // 找到最顶层的控制器，防止被遮挡
            while (rootVC.presentedViewController) {
                rootVC = rootVC.presentedViewController;
            }

            // 构造弹窗
            NSString *msg = [NSString stringWithFormat:@"🎉 插件加载成功！\n\n如果看到这个弹窗，说明注入路径是对的。\n\n当前伪装 ID:\n%@", kTargetBundleID];
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"💉 注入调试器"
                                                                           message:msg
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"Nice" style:UIAlertActionStyleDefault handler:nil]];

            [rootVC presentViewController:alert animated:YES completion:nil];
            NSLog(@"[DebugPlugin] ✅ 弹窗已发送给 UI");
        } else {
            NSLog(@"[DebugPlugin] ❌ 未找到 UIWindow，无法弹窗 (但插件已加载)");
        }
    });
}

// ----------------------------------------------------------------
// 🛡️ 2. Hook 逻辑 (之前的代码保留)
// ----------------------------------------------------------------

@implementation NSBundle (Stealth)

- (NSString *)stealth_bundleIdentifier {
    return kTargetBundleID;
}

- (NSDictionary *)stealth_infoDictionary {
    NSMutableDictionary *dict = [[self stealth_infoDictionary] mutableCopy];
    if (dict) {
        dict[@"CFBundleIdentifier"] = kTargetBundleID;
    }
    return dict;
}

- (id)stealth_objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kTargetBundleID;
    }
    return [self stealth_objectForInfoDictionaryKey:key];
}

@end

__attribute__((constructor)) static void HookEntry() {
    // 简单的 OC Swizzle
    Method orig = class_getInstanceMethod([NSBundle class], @selector(bundleIdentifier));
    Method hook = class_getInstanceMethod([NSBundle class], @selector(stealth_bundleIdentifier));
    if (orig && hook) method_exchangeImplementations(orig, hook);
    
    Method origInfo = class_getInstanceMethod([NSBundle class], @selector(infoDictionary));
    Method hookInfo = class_getInstanceMethod([NSBundle class], @selector(stealth_infoDictionary));
    if (origInfo && hookInfo) method_exchangeImplementations(origInfo, hookInfo);
    
    Method origKey = class_getInstanceMethod([NSBundle class], @selector(objectForInfoDictionaryKey:));
    Method hookKey = class_getInstanceMethod([NSBundle class], @selector(stealth_objectForInfoDictionaryKey:));
    if (origKey && hookKey) method_exchangeImplementations(origKey, hookKey);
}
