#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// =======================================================
// ⚙️ 用户配置
// =======================================================
static NSString *const kFakeBundleID = @"com.xingin.discover";
// =======================================================


@implementation NSBundle (FakeID)

// 1. 伪装 bundleIdentifier
- (NSString *)fake_bundleIdentifier {
    // 直接返回假 ID
    return kFakeBundleID;
}

// 2. 伪装 objectForInfoDictionaryKey
- (id)fake_objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kFakeBundleID;
    }
    // 调用原方法（因为我们交换了实现，所以这里调用 fake 其实是调用的原方法）
    return [self fake_objectForInfoDictionaryKey:key];
}

// 3. 伪装 infoDictionary
- (NSDictionary *)fake_infoDictionary {
    // 调用原方法拿到真字典
    NSDictionary *originalDict = [self fake_infoDictionary];
    if (originalDict) {
        NSMutableDictionary *newDict = [originalDict mutableCopy];
        newDict[@"CFBundleIdentifier"] = kFakeBundleID;
        return newDict;
    }
    return originalDict;
}

@end


// ----------------------------------------------------------------
// 核心逻辑：Swizzling (交换方法实现)
// ----------------------------------------------------------------
void ExchangeMethod(Class cls, SEL originalSelector, SEL swizzledSelector) {
    Method originalMethod = class_getInstanceMethod(cls, originalSelector);
    Method swizzledMethod = class_getInstanceMethod(cls, swizzledSelector);
    
    BOOL didAddMethod = class_addMethod(cls, 
                                        originalSelector, 
                                        method_getImplementation(swizzledMethod), 
                                        method_getTypeEncoding(swizzledMethod));
    
    if (didAddMethod) {
        class_replaceMethod(cls, 
                            swizzledSelector, 
                            method_getImplementation(originalMethod), 
                            method_getTypeEncoding(originalMethod));
    } else {
        method_exchangeImplementations(originalMethod, swizzledMethod);
    }
}

// ----------------------------------------------------------------
// 启动入口：dylib 加载时自动执行
// ----------------------------------------------------------------
__attribute__((constructor)) static void EntryPoint() {
    NSLog(@"[FakeBundleID] Plugin Loaded! Start Swizzling...");
    
    // 执行交换
    ExchangeMethod([NSBundle class], @selector(bundleIdentifier), @selector(fake_bundleIdentifier));
    ExchangeMethod([NSBundle class], @selector(objectForInfoDictionaryKey:), @selector(fake_objectForInfoDictionaryKey:));
    ExchangeMethod([NSBundle class], @selector(infoDictionary), @selector(fake_infoDictionary));
    
    // 弹窗验证 (延迟3秒)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *currentID = [[NSBundle mainBundle] bundleIdentifier];
            
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"✅ 纯净版插件生效"
                                                                           message:[NSString stringWithFormat:@"当前伪装 ID:\n%@", currentID]
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            
            // 安全获取 UIWindow
            UIWindow *win = nil;
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
    });
}
