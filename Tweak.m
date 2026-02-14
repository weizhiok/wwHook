#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h> // 震动支持
#import <objc/runtime.h>

// =======================================================
// ⚙️ 配置：你的目标假 ID
// =======================================================
static NSString * const kTargetBundleID = @"com.user.bundlechecker";
// =======================================================

// ----------------------------------------------------------------
// 🛡️ 1. 定义要欺骗的方法 (OC Category)
// ----------------------------------------------------------------
@implementation NSBundle (Stealth)

// 伪造 bundleIdentifier
- (NSString *)stealth_bundleIdentifier {
    return kTargetBundleID;
}

// 伪造 infoDictionary (这是很多检测工具的后门)
- (NSDictionary *)stealth_infoDictionary {
    // 1. 获取原始字典
    NSDictionary *originalDict = [self stealth_infoDictionary];
    
    // 2. 如果字典存在，不仅要防崩溃，还要修改它
    if (originalDict && [originalDict isKindOfClass:[NSDictionary class]]) {
        // 深拷贝一份，防止修改原始数据导致系统异常
        NSMutableDictionary *newDict = [originalDict mutableCopy];
        
        // 修改核心 ID
        newDict[@"CFBundleIdentifier"] = kTargetBundleID;
        
        // 顺手把版本号也保护一下（可选）
        // newDict[@"CFBundleShortVersionString"] = @"1.0.0";
        
        return newDict;
    }
    return originalDict;
}

// 伪造 objectForInfoDictionaryKey
- (id)stealth_objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kTargetBundleID;
    }
    return [self stealth_objectForInfoDictionaryKey:key];
}

@end

// ----------------------------------------------------------------
// ⚡️ 2. 核弹级入口：构造函数 (Constructor)
// ----------------------------------------------------------------
// 这个函数会在 App 的 main() 函数之前执行
// 优先级：插件 > App 主程序
__attribute__((constructor)) static void EntryPoint() {
    
    // ---------------------------------------------------
    // 第一步：震动 (Physically Verify)
    // ---------------------------------------------------
    // 只要手机一震，说明你的插件已经接管了进程
    AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
    NSLog(@"[FinalHook] ⚡️ 插件已加载，正在执行拦截...");

    // ---------------------------------------------------
    // 第二步：立即 Hook (Zero Latency)
    // ---------------------------------------------------
    // 不用 dispatch_after，不用 wait，直接动手！
    // 因为这是纯 OC 运行时交换，不涉及 UI，iOS 18 是允许的。
    
    Class cls = [NSBundle class];
    
    // 1. Hook bundleIdentifier
    Method m1 = class_getInstanceMethod(cls, @selector(bundleIdentifier));
    Method m2 = class_getInstanceMethod(cls, @selector(stealth_bundleIdentifier));
    if (m1 && m2) method_exchangeImplementations(m1, m2);
    
    // 2. Hook infoDictionary
    Method m3 = class_getInstanceMethod(cls, @selector(infoDictionary));
    Method m4 = class_getInstanceMethod(cls, @selector(stealth_infoDictionary));
    if (m3 && m4) method_exchangeImplementations(m3, m4);
    
    // 3. Hook objectForInfoDictionaryKey
    Method m5 = class_getInstanceMethod(cls, @selector(objectForInfoDictionaryKey:));
    Method m6 = class_getInstanceMethod(cls, @selector(stealth_objectForInfoDictionaryKey:));
    if (m5 && m6) method_exchangeImplementations(m5, m6);
    
    NSLog(@"[FinalHook] ✅ 拦截网已部署完毕 (Main函数启动前)");
}
