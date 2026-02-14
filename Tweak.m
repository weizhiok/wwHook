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
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
            NSLog(@"[Stealth] ⚡️ 震动触发 - 注入成功");
        });

        // 2. 核心：切到主线程排队 (避开启动检查)
        dispatch_async(dispatch_get_main_queue(), ^{
            NSLog(@"[Stealth] 🚀 主线程启动，开始执行全量 OC 拦截...");
            
            // 部署拦截网：拦截 NSBundle 的所有数据出口
            [self swizzleInstanceMethod:@selector(bundleIdentifier) with:@selector(hook_bundleIdentifier)];
            [self swizzleInstanceMethod:@selector(infoDictionary) with:@selector(hook_infoDictionary)];
            [self swizzleInstanceMethod:@selector(localizedInfoDictionary) with:@selector(hook_localizedInfoDictionary)];
            [self swizzleInstanceMethod:@selector(objectForInfoDictionaryKey:) with:@selector(hook_objectForInfoDictionaryKey:)];
            
            NSLog(@"[Stealth] ✅ 拦截网部署完成");
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
// 🛡️ Hook 实现逻辑 (全维度覆盖)
// ----------------------------------------------------------------

// 1. 直接拦截 bundleID
- (NSString *)hook_bundleIdentifier {
    return kTargetBundleID;
}

// 2. 拦截主字典 (C API 经常读这里)
- (NSDictionary *)hook_infoDictionary {
    NSDictionary *originalDict = [self hook_infoDictionary]; // 调用原方法
    
    if (originalDict && [originalDict isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *newDict = [originalDict mutableCopy];
        // 修改核心 ID
        newDict[@"CFBundleIdentifier"] = kTargetBundleID;
        // 顺手补全 TeamID 等信息，增加可信度
        // newDict[@"AppIdentifierPrefix"] = @"ABCDE12345."; 
        return newDict;
    }
    return originalDict;
}

// 3. 拦截本地化字典 (部分 API 读这里)
- (NSDictionary *)hook_localizedInfoDictionary {
    NSDictionary *originalDict = [self hook_localizedInfoDictionary]; // 调用原方法
    
    if (originalDict && [originalDict isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *newDict = [originalDict mutableCopy];
        newDict[@"CFBundleIdentifier"] = kTargetBundleID;
        return newDict;
    }
    // 如果本地化字典为空，回退到主字典的逻辑（不做额外处理，防止死循环）
    return originalDict;
}

// 4. 拦截 Key 查询
- (id)hook_objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kTargetBundleID;
    }
    // 必须返回原值，否则启动必崩
    return [self hook_objectForInfoDictionaryKey:key];
}

@end
