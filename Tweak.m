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
// ⚡️ 核心入口：+load (App 启动前自动执行)
// ----------------------------------------------------------------
+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        // 1. 震动反馈 (证明注入成功)
        // 放在后台线程，绝对不卡死主线程
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
            NSLog(@"[Stealth] ⚡️ 震动触发 - 注入成功");
        });

        // 2. 执行交换 (Swizzling)
        [self swizzleInstanceMethod:@selector(bundleIdentifier) with:@selector(hook_bundleIdentifier)];
        [self swizzleInstanceMethod:@selector(infoDictionary) with:@selector(hook_infoDictionary)];
        [self swizzleInstanceMethod:@selector(objectForInfoDictionaryKey:) with:@selector(hook_objectForInfoDictionaryKey:)];
        
        NSLog(@"[Stealth] ✅ 拦截网部署完成");
    });
}

// ----------------------------------------------------------------
// 🛠 辅助工具：安全的交换方法
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
// 🛡️ Hook 实现逻辑 (关键修复点)
// ----------------------------------------------------------------

// 1. 伪装 bundleIdentifier
- (NSString *)hook_bundleIdentifier {
    // 直接返回假 ID
    return kTargetBundleID;
}

// 2. 伪装 infoDictionary (这里是之前闪退的根源，现在修复了)
- (NSDictionary *)hook_infoDictionary {
    // 🟢 关键：先调用原方法获取完整数据！
    // 注意：因为已经交换了 IMP，这里调用 [self hook_infoDictionary] 实际上是调用系统的 [self infoDictionary]
    NSDictionary *originalDict = [self hook_infoDictionary];
    
    if (originalDict && [originalDict isKindOfClass:[NSDictionary class]]) {
        // 🟢 关键：在保留原始数据的基础上，只修改 ID
        NSMutableDictionary *newDict = [originalDict mutableCopy];
        newDict[@"CFBundleIdentifier"] = kTargetBundleID;
        return newDict;
    }
    return originalDict;
}

// 3. 伪装 objectForInfoDictionaryKey
- (id)hook_objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kTargetBundleID;
    }
    // 🟢 关键：其他 key 必须返回原值！否则 App 读不到 MainStoryboard 就会闪退
    return [self hook_objectForInfoDictionaryKey:key];
}

@end
