#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h>
#import <objc/runtime.h>

// =======================================================
// ⚙️ 配置：目标假 ID
// =======================================================
static NSString * const kTargetBundleID = @"com.user.bundlechecker";
// =======================================================

@implementation NSBundle (Stealth)

// ----------------------------------------------------------------
// ⚡️ 核心入口：+load
// ----------------------------------------------------------------
+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        // 1. 震动反馈 (证明注入成功)
        // 放在后台线程，防止阻塞
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
            NSLog(@"[Stealth] ⚡️ 震动触发 - 注入成功");
        });

        // 2. 执行交换 (只做最稳的一个！)
        // ⚠️ 暂时砍掉 infoDictionary，先保证不闪退
        [self swizzleInstanceMethod:@selector(bundleIdentifier) with:@selector(hook_bundleIdentifier)];
        
        // 这个也比较安全，可以保留
        [self swizzleInstanceMethod:@selector(objectForInfoDictionaryKey:) with:@selector(hook_objectForInfoDictionaryKey:)];
        
        NSLog(@"[Stealth] ✅ 基础拦截已部署 (安全模式)");
    });
}

// ----------------------------------------------------------------
// 🛠 辅助工具
// ----------------------------------------------------------------
+ (void)swizzleInstanceMethod:(SEL)originalSel with:(SEL)newSel {
    Class class = [self class];
    Method originalMethod = class_getInstanceMethod(class, originalSel);
    Method newMethod = class_getInstanceMethod(class, newSel);

    if (class_addMethod(class, originalSel, method_getImplementation(newMethod), method_getTypeEncoding(newMethod))) {
        class_replaceMethod(class, newSel, method_getImplementation(originalMethod), method_getTypeEncoding(originalMethod));
    } else {
        method_exchangeImplementations(originalMethod, newMethod);
    }
}

// ----------------------------------------------------------------
// 🛡️ Hook 实现逻辑
// ----------------------------------------------------------------

// 1. 伪装 bundleIdentifier (最安全，绝对不会崩)
- (NSString *)hook_bundleIdentifier {
    return kTargetBundleID;
}

// 2. 伪装 objectForInfoDictionaryKey
- (id)hook_objectForInfoDictionaryKey:(NSString *)key {
    // 只拦截 ID，其他一律放行，防止误伤系统配置
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kTargetBundleID;
    }
    // 必须调用原方法返回其他值 (如 UIMainStoryboardFile)
    return [self hook_objectForInfoDictionaryKey:key];
}

/* ⚠️ 暂时注释掉这个“高危”方法，等 App 能启动了再说
- (NSDictionary *)hook_infoDictionary {
    NSDictionary *originalDict = [self hook_infoDictionary];
    if (originalDict && [originalDict isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *newDict = [originalDict mutableCopy];
        newDict[@"CFBundleIdentifier"] = kTargetBundleID;
        return newDict;
    }
    return originalDict;
}
*/

@end
