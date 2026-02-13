#import <Foundation/Foundation.h>
#import <objc/runtime.h>

// =======================================================
// ⚙️ 纯净版配置
// =======================================================
static NSString *const kFakeBundleID = @"com.xingin.discover";
// =======================================================

@implementation NSBundle (FakeID)

// 1. 伪装 bundleIdentifier
- (NSString *)fake_bundleIdentifier {
    return kFakeBundleID;
}

// 2. 伪装 objectForInfoDictionaryKey
- (id)fake_objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kFakeBundleID;
    }
    return [self fake_objectForInfoDictionaryKey:key];
}

// 3. 伪装 infoDictionary
- (NSDictionary *)fake_infoDictionary {
    NSDictionary *originalDict = [self fake_infoDictionary];
    if (originalDict && [originalDict isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *newDict = [originalDict mutableCopy];
        newDict[@"CFBundleIdentifier"] = kFakeBundleID;
        return newDict;
    }
    return originalDict;
}

@end

// ----------------------------------------------------------------
// 核心逻辑：Swizzling (只交换方法，不执行任何其他代码)
// ----------------------------------------------------------------
static void ExchangeMethod(Class cls, SEL originalSelector, SEL swizzledSelector) {
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
// 启动入口
// ----------------------------------------------------------------
__attribute__((constructor)) static void EntryPoint() {
    // ⚠️ 删除了所有 NSLog 和 弹窗代码，确保 0 副作用
    ExchangeMethod([NSBundle class], @selector(bundleIdentifier), @selector(fake_bundleIdentifier));
    ExchangeMethod([NSBundle class], @selector(objectForInfoDictionaryKey:), @selector(fake_objectForInfoDictionaryKey:));
    ExchangeMethod([NSBundle class], @selector(infoDictionary), @selector(fake_infoDictionary));
}
