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
        
        // 1. 震动反馈 (保留，确认注入成功)
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
            NSLog(@"[Stealth] ⚡️ 震动触发 - 注入成功");
        });

        // 2. 切到主线程执行“内存手术”
        dispatch_async(dispatch_get_main_queue(), ^{
            NSLog(@"[Stealth] 🚀 主线程启动，开始执行 Ivar 替换...");
            
            // 执行替换逻辑
            [self injectModifiedDictionary];
            
            // 为了双重保险，保留唯一的、最稳的 bundleIdentifier Hook
            // (这个方法几乎不会崩，而且能保证 OC API 100% 变绿)
            [self swizzleInstanceMethod:@selector(bundleIdentifier) with:@selector(hook_bundleIdentifier)];
            
            NSLog(@"[Stealth] ✅ 内存手术完成");
        });
    });
}

// ----------------------------------------------------------------
// 🔪 核心手术：直接修改 _infoDictionary 内存变量
// ----------------------------------------------------------------
+ (void)injectModifiedDictionary {
    NSBundle *mainBundle = [NSBundle mainBundle];
    
    // 1. 获取原始字典
    // 注意：这里直接读属性，避免触发由于 Swizzle 导致的死循环
    NSDictionary *originalDict = [mainBundle infoDictionary];
    
    if (originalDict) {
        // 2. 构造假字典
        NSMutableDictionary *newDict = [originalDict mutableCopy];
        newDict[@"CFBundleIdentifier"] = kTargetBundleID;
        // 还可以顺便改改版本号，做戏做全套
        // newDict[@"CFBundleShortVersionString"] = @"9.9.9";
        
        // 3. 利用 Runtime 查找私有变量 _infoDictionary
        // 这是 NSBundle 存放数据的真实位置
        Ivar ivar = class_getInstanceVariable([NSBundle class], "_infoDictionary");
        
        if (ivar) {
            // 4. 强行替换内存中的对象！
            // 这一步之后，无论谁调用 [NSBundle infoDictionary]，拿到的都是 newDict
            // 甚至底层的某些 C API 如果共享这个对象，也会被骗到
            object_setIvar(mainBundle, ivar, newDict);
            NSLog(@"[Stealth] 💉 已成功替换 _infoDictionary 内存对象");
        } else {
            NSLog(@"[Stealth] ⚠️ 未找到 _infoDictionary 变量，尝试备用方案");
            // 如果找不到变量（极少见），我们可能需要回退到 hook 方案，
            // 但为了不闪退，这里选择什么都不做，保命要紧。
        }
    }
}

// ----------------------------------------------------------------
// 🛠 辅助 Hook (仅保留最稳的一个)
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

// 只 Hook 这一个！因为这是 App 读取 ID 最直接的入口，且 crash 概率极低
- (NSString *)hook_bundleIdentifier {
    return kTargetBundleID;
}

@end
