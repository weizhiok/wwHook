#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h>
#import <objc/runtime.h>

// =======================================================
// ⚙️ 配置：目标假 ID
// =======================================================
static NSString * const kTargetBundleID = @"com.user.bundlechecker";
// =======================================================

// 我们定义一个伪装类，只为了利用它的 +load 方法
@interface StealthLoader : NSObject
@end

@implementation StealthLoader

// ⚡️ 核心入口：+load 方法
// 这个方法会在类加载时自动运行，早于 main 函数，且 ObjC 环境已准备就绪
+ (void)load {
    // ---------------------------------------------------
    // 1. 震动反馈 (放入异步线程，防止阻塞主线程导致闪退)
    // ---------------------------------------------------
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
        NSLog(@"[Stealth] ⚡️ 插件已加载 (Vibration Triggered)");
    });

    // ---------------------------------------------------
    // 2. 立即执行 Hook (同步执行，确保覆盖检测)
    // ---------------------------------------------------
    NSLog(@"[Stealth] 🛠 开始执行 Method Swizzling...");
    
    // 执行交换逻辑
    [self swizzleNSBundle];
    
    NSLog(@"[Stealth] ✅ Method Swizzling 完成");
}

+ (void)swizzleNSBundle {
    Class cls = [NSBundle class];
    
    // 定义我们要交换的方法对
    // 格式：{ 原方法 SEL, 新方法 SEL }
    struct { SEL original; SEL swizzled; } methods[] = {
        { @selector(bundleIdentifier), @selector(stealth_bundleIdentifier) },
        { @selector(infoDictionary), @selector(stealth_infoDictionary) },
        { @selector(objectForInfoDictionaryKey:), @selector(stealth_objectForInfoDictionaryKey:) }
    };
    
    int count = sizeof(methods) / sizeof(methods[0]);
    
    for (int i = 0; i < count; i++) {
        SEL origSEL = methods[i].original;
        SEL swizSEL = methods[i].swizzled;
        
        Method origMethod = class_getInstanceMethod(cls, origSEL);
        Method swizMethod = class_getInstanceMethod(self, swizSEL); // 注意：新方法实现在当前类(StealthLoader)里
        
        // 这里的逻辑是：把 NSBundle 的原方法，指向我们 StealthLoader 类里的新实现
        // 这种跨类 Swizzle 更安全，不容易导致无限递归
        if (origMethod && swizMethod) {
            method_exchangeImplementations(origMethod, swizMethod);
        }
    }
}

// ----------------------------------------------------------------
// 🛡️ 新的方法实现 (注意：这些方法会被添加到 NSBundle 上去)
// ----------------------------------------------------------------

- (NSString *)stealth_bundleIdentifier {
    return kTargetBundleID;
}

- (NSDictionary *)stealth_infoDictionary {
    // 因为跨类交换了，这里调用 [self stealth_infoDictionary] 实际上会回到 NSBundle 的原逻辑
    // 为了防止编译器警告，我们需要强制转换一下，或者使用 runtime 调用
    // 简单起见，我们假设如果能拿到原始字典就改，拿不到就返回 nil
    
    // 注意：这里是一个比较 tricky 的地方。为了防闪退，我们不调用原方法了，直接构建假数据。
    // 调用原方法在跨类交换时容易出问题。
    
    NSMutableDictionary *fakeDict = [NSMutableDictionary dictionary];
    fakeDict[@"CFBundleIdentifier"] = kTargetBundleID;
    fakeDict[@"CFBundleShortVersionString"] = @"1.0.0";
    fakeDict[@"CFBundleVersion"] = @"1";
    // 如果你需要更多字段，可以在这里手动补上
    
    return fakeDict;
}

- (id)stealth_objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kTargetBundleID;
    }
    // 如果不是查 ID，返回 nil 或者默认值 (为了防闪退，我们尽量少操作原对象)
    return nil; 
}

@end
