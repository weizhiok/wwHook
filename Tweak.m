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
// 🛡️ 准备好要 Hook 的方法，但先不执行
// ----------------------------------------------------------------
@implementation NSBundle (Stealth)

- (NSString *)stealth_bundleIdentifier {
    return kTargetBundleID;
}

- (NSDictionary *)stealth_infoDictionary {
    NSDictionary *originalDict = [self stealth_infoDictionary];
    if (originalDict && [originalDict isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *newDict = [originalDict mutableCopy];
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
// 🚀 核心入口：先活着，再动手
// ----------------------------------------------------------------
__attribute__((constructor)) static void ModuleEntry() {
    
    // 1. 震动：证明注入成功
    AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
    NSLog(@"[DelayHook] ⚡️ 震动触发，插件已加载，当前保持纯净状态...");

    // ⚠️ 此时不要 Hook！防止系统启动检查杀进程！

    // 2. 延迟 6 秒：等 App 完全启动进入首页，避开风头
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        NSLog(@"[DelayHook] ⏳ 安全时间已到，准备动手...");
        
        // ---------------------------------------------------
        // 第一阶段：先弹窗 (证明我们活过了启动期)
        // ---------------------------------------------------
        UIWindow *topWindow = nil;
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

            NSString *msg = [NSString stringWithFormat:@"✅ 存活确认！\n\n点击[开始伪装]后，将执行 Hook。\n\n目标 ID:\n%@", kTargetBundleID];
            
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🕵️‍♂️ 延迟注入系统"
                                                                           message:msg
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            
            // ---------------------------------------------------
            // 第二阶段：用户点击后才 Hook (最安全)
            // ---------------------------------------------------
            [alert addAction:[UIAlertAction actionWithTitle:@"开始伪装" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
                
                // 🔥 动手！执行 Swizzling
                Method orig = class_getInstanceMethod([NSBundle class], @selector(bundleIdentifier));
                Method hook = class_getInstanceMethod([NSBundle class], @selector(stealth_bundleIdentifier));
                if (orig && hook) method_exchangeImplementations(orig, hook);
                
                Method origInfo = class_getInstanceMethod([NSBundle class], @selector(infoDictionary));
                Method hookInfo = class_getInstanceMethod([NSBundle class], @selector(stealth_infoDictionary));
                if (origInfo && hookInfo) method_exchangeImplementations(origInfo, hookInfo);
                
                Method origKey = class_getInstanceMethod([NSBundle class], @selector(objectForInfoDictionaryKey:));
                Method hookKey = class_getInstanceMethod([NSBundle class], @selector(stealth_objectForInfoDictionaryKey:));
                if (origKey && hookKey) method_exchangeImplementations(origKey, hookKey);
                
                // 再震动一下提示成功
                AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
                NSLog(@"[DelayHook] ✅ Hook 已执行！");
            }]];
            
            [rootVC presentViewController:alert animated:YES completion:nil];
        }
    });
}
