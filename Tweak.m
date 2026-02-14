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
        
        // 1. 震动反馈 (证明 dylib 活着)
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
            NSLog(@"[Stealth] ⚡️ 震动触发 - dylib 已加载");
        });

        // 2. 核心修改：不要立即动手，去主线程排队！
        // 这会让 Hook 操作避开 dyld 的加载期检查，但在 App 业务逻辑开始前执行
        dispatch_async(dispatch_get_main_queue(), ^{
            NSLog(@"[Stealth] 🚀 主线程启动，开始执行拦截...");
            
            // 执行交换
            [self swizzleInstanceMethod:@selector(bundleIdentifier) with:@selector(hook_bundleIdentifier)];
            [self swizzleInstanceMethod:@selector(infoDictionary) with:@selector(hook_infoDictionary)];
            [self swizzleInstanceMethod:@selector(objectForInfoDictionaryKey:) with:@selector(hook_objectForInfoDictionaryKey:)];
            
            NSLog(@"[Stealth] ✅ 拦截网部署完成 (RunLoop Start)");
        });
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
// 🛡️ Hook 实现逻辑 (带原始数据回落，防崩)
// ----------------------------------------------------------------

// 1. 伪装 bundleIdentifier
- (NSString *)hook_bundleIdentifier {
    return kTargetBundleID;
}

// 2. 伪装 infoDictionary
- (NSDictionary *)hook_infoDictionary {
    // 先拿原始数据，保证 App 不会因为缺少 Key 而崩溃
    NSDictionary *originalDict = [self hook_infoDictionary];
    
    if (originalDict && [originalDict isKindOfClass:[NSDictionary class]]) {
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
    // 其他 Key 必须返回原值，否则启动必崩
    return [self hook_objectForInfoDictionaryKey:key];
}

@end
