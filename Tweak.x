#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>

// =======================================================
// ⚙️ 用户配置区域
// =======================================================
static NSString *const kFakeBundleID = @"com.xingin.discover"; 
static const double kAlertDelay = 10.0; 
// =======================================================

@interface LSApplicationProxy : NSObject
+ (id)applicationProxyForIdentifier:(id)arg1;
@property(readonly, nonatomic) NSString *applicationIdentifier;
@property(readonly, nonatomic) NSString *bundleIdentifier;
@end

// ----------------------------------------------------------------
// 第一部分：Objective-C 层拦截
// ----------------------------------------------------------------
%hook NSBundle

- (NSString *)bundleIdentifier {
    return kFakeBundleID;
}

- (id)objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kFakeBundleID;
    }
    return %orig;
}

- (NSDictionary *)infoDictionary {
    NSMutableDictionary *dict = [%orig mutableCopy];
    if (dict) {
        dict[@"CFBundleIdentifier"] = kFakeBundleID;
    }
    return dict;
}

- (NSDictionary *)localizedInfoDictionary {
    NSMutableDictionary *dict = [%orig mutableCopy];
    if (dict) {
        dict[@"CFBundleIdentifier"] = kFakeBundleID;
    }
    return dict;
}

%end

// ----------------------------------------------------------------
// 第二部分：C 语言底层拦截 (已修复 ARC 报错)
// ----------------------------------------------------------------

%hookf(CFStringRef, CFBundleGetIdentifier, CFBundleRef bundle) {
    if (bundle == CFBundleGetMainBundle()) {
        // 修复点 1: 添加 (__bridge CFStringRef)
        return (__bridge CFStringRef)kFakeBundleID;
    }
    return %orig(bundle);
}

%hookf(const void *, CFBundleGetValueForInfoDictionaryKey, CFBundleRef bundle, CFStringRef key) {
    if (CFStringCompare(key, kCFBundleIdentifierKey, 0) == kCFCompareEqualTo) {
        if (bundle == CFBundleGetMainBundle()) {
            // 修复点 2: 添加 (__bridge const void *)
            return (__bridge const void *)kFakeBundleID;
        }
    }
    return %orig(bundle, key);
}


// ----------------------------------------------------------------
// 第三部分：文件 I/O 拦截
// ----------------------------------------------------------------
%hook NSDictionary

+ (id)dictionaryWithContentsOfFile:(NSString *)path {
    id result = %orig(path);
    if (result && path && [path hasSuffix:@"Info.plist"]) {
        if ([path rangeOfString:[[NSBundle mainBundle] bundlePath]].location != NSNotFound) {
            NSMutableDictionary *mutableDict = [result mutableCopy];
            mutableDict[@"CFBundleIdentifier"] = kFakeBundleID;
            return mutableDict;
        }
    }
    return result;
}

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
// 第四部分：私有 API 拦截
// ----------------------------------------------------------------
%hook LSApplicationProxy

- (NSString *)bundleIdentifier {
    return kFakeBundleID;
}

- (NSString *)applicationIdentifier {
    return kFakeBundleID;
}

%end


// ----------------------------------------------------------------
// 第五部分：弹窗验证 (已修复 keyWindow 报错)
// ----------------------------------------------------------------
%hook UIApplication

- (void)applicationDidFinishLaunching:(id)application {
    %orig;
    
    if (kAlertDelay <= 0) {
        return;
    }
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kAlertDelay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        // 修复点: 同样使用 bridge 转换
        NSString *checkID = (__bridge NSString *)CFBundleGetIdentifier(CFBundleGetMainBundle());
        
        NSString *msg = [NSString stringWithFormat:@"终极拦截已生效\n\n当前 APP 识别到的 ID:\n%@", checkID];
        
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🛡️ BundleID 伪装" 
                                                                       message:msg
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
        
        // 修复点 3: 忽略 keyWindow 过时警告
        UIWindow *win = nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        win = [UIApplication sharedApplication].keyWindow;
#pragma clang diagnostic pop
        
        UIViewController *rootVC = win.rootViewController;
        while (rootVC.presentedViewController) {
            rootVC = rootVC.presentedViewController;
        }
        [rootVC presentViewController:alert animated:YES completion:nil];
    });
}

%end
