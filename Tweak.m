#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h> // 震动支持
#import <objc/runtime.h>

// =======================================================
// ⚙️ 目标 BundleID
// =======================================================
static NSString * const kTargetBundleID = @"com.user.bundlechecker";
// =======================================================

// ----------------------------------------------------------------
// 🛡️ 1. 最稳的 OC Swizzling (只欺骗 [NSBundle bundleIdentifier])
// ----------------------------------------------------------------
@implementation NSBundle (Stealth)

- (NSString *)stealth_bundleIdentifier {
    // 直接返回假 ID
    return kTargetBundleID;
}

- (NSDictionary *)stealth_infoDictionary {
    // 获取真字典
    NSDictionary *originalDict = [self stealth_infoDictionary];
    if (originalDict && [originalDict isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *newDict = [originalDict mutableCopy];
        // 修改字典里的 ID
        newDict[@"CFBundleIdentifier"] = kTargetBundleID;
        return newDict;
    }
    return originalDict;
}

- (id)stealth_objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kTargetBundleID;
    }
    return [self stealth_objectForInfoDictionaryKey:key];
}

@end

// ----------------------------------------------------------------
// 🚀 2. 构造函数：执行交换 + 弹窗验证
// ----------------------------------------------------------------
__attribute__((constructor)) static void ModuleEntry() {
    
    // ---------------------------------------------------
    // 第一步：震动 (最直接的物理反馈)
    // ---------------------------------------------------
    AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
    NSLog(@"[SafePlugin] ⚡️ 震动已触发，插件已加载！");

    // ---------------------------------------------------
    // 第二步：执行安全的 OC Method Swizzling
    // ---------------------------------------------------
    Method orig = class_getInstanceMethod([NSBundle class], @selector(bundleIdentifier));
    Method hook = class_getInstanceMethod([NSBundle class], @selector(stealth_bundleIdentifier));
    if (orig && hook) method_exchangeImplementations(orig, hook);
    
    Method origInfo = class_getInstanceMethod([NSBundle class], @selector(infoDictionary));
    Method hookInfo = class_getInstanceMethod([NSBundle class], @selector(stealth_infoDictionary));
    if (origInfo && hookInfo) method_exchangeImplementations(origInfo, hookInfo);
    
    Method origKey = class_getInstanceMethod([NSBundle class], @selector(objectForInfoDictionaryKey:));
    Method hookKey = class_getInstanceMethod([NSBundle class], @selector(stealth_objectForInfoDictionaryKey:));
    if (origKey && hookKey) method_exchangeImplementations(origKey, hookKey);
    
    NSLog(@"[SafePlugin] ✅ OC Swizzling 已完成");

    // ---------------------------------------------------
    // 第三步：延时弹窗 (视觉反馈)
    // ---------------------------------------------------
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        NSLog(@"[SafePlugin] ⏰ 准备弹窗...");
        
        UIWindow *topWindow = nil;
        // 兼容 iOS 13-18 的窗口获取逻辑
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                if (scene.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *w in scene.windows) {
                        if (w.isKeyWindow) { topWindow = w; break; }
                    }
                }
            }
        }
        if (!topWindow) topWindow = [UIApplication sharedApplication].windows.firstObject;

        if (topWindow) {
            UIViewController *rootVC = topWindow.rootViewController;
            while (rootVC.presentedViewController) rootVC = rootVC.presentedViewController;

            NSString *msg = [NSString stringWithFormat:@"✅ 稳定版插件运行中\n\n如果 App 没有闪退，说明注入环境完美！\n\n当前伪装 ID:\n%@", kTargetBundleID];
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🛡️ 安全模式"
                                                                           message:msg
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"Nice" style:UIAlertActionStyleDefault handler:nil]];
            
            [rootVC presentViewController:alert animated:YES completion:nil];
        } else {
             NSLog(@"[SafePlugin] ❌ 没找到窗口，但代码没崩");
        }
    });
}
