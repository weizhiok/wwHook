#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>

// =======================================================
// ⚙️ 沙盒安全版配置 (针对 iOS 18 证书签名优化)
// =======================================================
static NSString *const kFakeBundleID = @"com.xingin.discover"; 
static const double kAlertDelay = 8.0; 
// =======================================================

// ----------------------------------------------------------------
// 第一部分：Objective-C 层拦截 (最稳，不闪退)
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
// 第二部分：基础 C 语言拦截 (保留最核心的一个)
// ----------------------------------------------------------------

%hookf(CFStringRef, CFBundleGetIdentifier, CFBundleRef bundle) {
    if (bundle == CFBundleGetMainBundle()) {
        // 使用安全转换，防止内存报错
        return (__bridge CFStringRef)kFakeBundleID;
    }
    return %orig(bundle);
}


// ----------------------------------------------------------------
// 第三部分：文件读取拦截 (安全版)
// ----------------------------------------------------------------
%hook NSDictionary

+ (id)dictionaryWithContentsOfFile:(NSString *)path {
    id result = %orig(path);
    if (result && path && [path hasSuffix:@"Info.plist"]) {
        // 增加更严格的判断，防止误伤其他文件导致闪退
        if ([path rangeOfString:[[NSBundle mainBundle] bundlePath]].location != NSNotFound) {
            NSMutableDictionary *mutableDict = [result mutableCopy];
            mutableDict[@"CFBundleIdentifier"] = kFakeBundleID;
            return mutableDict;
        }
    }
    return result;
}

%end


// ----------------------------------------------------------------
// 第四部分：弹窗验证
// ----------------------------------------------------------------
%hook UIApplication

- (void)applicationDidFinishLaunching:(id)application {
    %orig;
    
    if (kAlertDelay <= 0) {
        return;
    }
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kAlertDelay * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        // 简单获取，防止调用底层 API 导致崩溃
        NSString *checkID = [[NSBundle mainBundle] bundleIdentifier];
        
        NSString *msg = [NSString stringWithFormat:@"✅ 安全模式启动\n伪装 ID:\n%@", checkID];
        
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"插件已生效" 
                                                                       message:msg
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Nice" style:UIAlertActionStyleDefault handler:nil]];
        
        // 安全获取 UIWindow
        UIWindow *win = nil;
        // 尝试获取 keyWindow，失败则遍历
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                 if (scene.activationState == UISceneActivationStateForegroundActive) {
                     for (UIWindow *w in scene.windows) {
                         if (w.isKeyWindow) {
                             win = w;
                             break;
                         }
                     }
                 }
            }
        }
        if (!win) win = [UIApplication sharedApplication].windows.firstObject;
        
        [win.rootViewController presentViewController:alert animated:YES completion:nil];
    });
}

%end
