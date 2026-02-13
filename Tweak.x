#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>

// =======================================================
// ⚙️ 用户配置区域 (在此修改 ID 和 弹窗时间)
// =======================================================

// 1. 设置你想要伪装成的 官方 BundleID
static NSString *const kFakeBundleID = @"com.xingin.discover"; 

// 2. 弹窗延迟开关 (单位：秒)
//    设置为 0.0  -> 关闭弹窗 (静默模式)
//    设置为 10.0 -> 延迟 10 秒后弹窗
static const double kAlertDelay = 10.0; 

// =======================================================


// --- 声明私有类 LSApplicationProxy (大厂风控常用来绕过检测) ---
@interface LSApplicationProxy : NSObject
+ (id)applicationProxyForIdentifier:(id)arg1;
@property(readonly, nonatomic) NSString *applicationIdentifier;
@property(readonly, nonatomic) NSString *bundleIdentifier;
@end

// ----------------------------------------------------------------
// 第一部分：Objective-C 层拦截 (NSBundle)
// 针对：绝大多数常规 APP 的检测
// ----------------------------------------------------------------
%hook NSBundle

// 拦截手段 1: [[NSBundle mainBundle] bundleIdentifier]
// 最常用的获取方式
- (NSString *)bundleIdentifier {
    return kFakeBundleID;
}

// 拦截手段 2: objectForInfoDictionaryKey:@"CFBundleIdentifier"
// 很多 APP 喜欢用 key 来取值
- (id)objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kFakeBundleID;
    }
    return %orig;
}

// 拦截手段 3: infoDictionary
// 防止 APP 遍历字典查出真相
- (NSDictionary *)infoDictionary {
    NSMutableDictionary *dict = [%orig mutableCopy];
    if (dict) {
        dict[@"CFBundleIdentifier"] = kFakeBundleID;
    }
    return dict;
}

// 拦截手段 4: localizedInfoDictionary
// 国际化字典，补漏用
- (NSDictionary *)localizedInfoDictionary {
    NSMutableDictionary *dict = [%orig mutableCopy];
    if (dict) {
        dict[@"CFBundleIdentifier"] = kFakeBundleID;
    }
    return dict;
}

%end

// ----------------------------------------------------------------
// 第二部分：C 语言底层拦截 (CoreFoundation)
// 针对：使用 C/C++ 编写的底层安全库
// ----------------------------------------------------------------

// 拦截手段 5: CFBundleGetIdentifier
// 这是 C 语言最底层的获取函数，如果不 Hook 这个，上述 OC 方法全失效
%hookf(CFStringRef, CFBundleGetIdentifier, CFBundleRef bundle) {
    // 只有当查询的是“主程序”时才撒谎，避免破坏系统组件
    if (bundle == CFBundleGetMainBundle()) {
        return (CFStringRef)kFakeBundleID;
    }
    return %orig(bundle);
}

// 拦截手段 6: CFBundleGetValueForInfoDictionaryKey
// 对应 OC 的 objectForInfoDictionaryKey，但是是 C 语言版
%hookf(const void *, CFBundleGetValueForInfoDictionaryKey, CFBundleRef bundle, CFStringRef key) {
    if (CFStringCompare(key, kCFBundleIdentifierKey, 0) == kCFCompareEqualTo) {
        if (bundle == CFBundleGetMainBundle()) {
            return (const void *)kFakeBundleID;
        }
    }
    return %orig(bundle, key);
}


// ----------------------------------------------------------------
// 第三部分：文件 I/O 拦截
// 针对：绕过系统 API，直接读取 Info.plist 文件的“鸡贼”检测
// ----------------------------------------------------------------
%hook NSDictionary

// 拦截手段 7: dictionaryWithContentsOfFile
// 当 APP 试图读取文件时触发
+ (id)dictionaryWithContentsOfFile:(NSString *)path {
    id result = %orig(path);
    // 性能优化：只处理 Info.plist，防止 APP 卡死
    if (result && path && [path hasSuffix:@"Info.plist"]) {
        // 进一步判断路径是否属于当前 APP
        if ([path rangeOfString:[[NSBundle mainBundle] bundlePath]].location != NSNotFound) {
            NSMutableDictionary *mutableDict = [result mutableCopy];
            mutableDict[@"CFBundleIdentifier"] = kFakeBundleID;
            return mutableDict;
        }
    }
    return result;
}

// 拦截手段 8: dictionaryWithContentsOfURL
// 同上，处理 URL 形式的读取
+ (id)dictionaryWithContentsOfURL:(NSURL *)url {
    id result = %orig(url);
    if (result && url && [[url path] hasSuffix:@"Info.plist"]) {
        if ([[url path] rangeOfString:[[NSBundle mainBundle] bundlePath]].location != NSNotFound) {
            NSMutableDictionary *mutableDict = [result mutableCopy];
            mutableDict[@"CFBundleIdentifier"] = kFakeBundleID;
            return mutableDict;
        }
    }
    return result;
}

%end


// ----------------------------------------------------------------
// 第四部分：私有 API 拦截 (LSApplicationProxy)
// 针对：大厂 App (小红书/微信) 的高级风控
// ----------------------------------------------------------------
%hook LSApplicationProxy

// 拦截手段 9: [LSApplicationProxy bundleIdentifier]
// 这是一个系统服务调用，不经过 NSBundle
- (NSString *)bundleIdentifier {
    return kFakeBundleID;
}

// 拦截手段 10: applicationIdentifier
- (NSString *)applicationIdentifier {
    return kFakeBundleID;
}

%end


// ----------------------------------------------------------------
// 第五部分：弹窗验证逻辑 (带开关)
// ----------------------------------------------------------------
%hook UIApplication

- (void)applicationDidFinishLaunching:(id)application {
    %orig;
    
    // 如果延迟设为 0，直接返回，不弹窗
    if (kAlertDelay <= 0) {
        return;
    }
    
    // 延迟执行
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kAlertDelay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        // 再次使用 C 语言底层方法验证，确保 Hook 生效
        NSString *checkID = (__bridge NSString *)CFBundleGetIdentifier(CFBundleGetMainBundle());
        
        NSString *msg = [NSString stringWithFormat:@"终极拦截已生效\n\n当前 APP 识别到的 ID:\n%@", checkID];
        
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🛡️ BundleID 伪装" 
                                                                       message:msg
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
        
        // 获取最顶层控制器进行弹窗
        UIViewController *rootVC = [UIApplication sharedApplication].keyWindow.rootViewController;
        while (rootVC.presentedViewController) {
            rootVC = rootVC.presentedViewController;
        }
        [rootVC presentViewController:alert animated:YES completion:nil];
    });
}

%end
