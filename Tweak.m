#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <objc/runtime.h>

// =======================================================
// ⚙️ 配置：目标假 ID
// =======================================================
static NSString * const kTargetBundleID = @"com.xingin.discover";
// =======================================================

// 全局变量：用于存储我们伪造的 Info.plist 文件的路径
static NSString *gFakePlistPath = nil;

// ----------------------------------------------------------------
// 🐟 增强版 Fishhook (支持 Lazy + Non-Lazy)
// ----------------------------------------------------------------
#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

struct rebind_entry {
    const char *name;
    void *replacement;
    void **replaced;
};

static void safe_write_pointer(void **target, void *replacement) {
    kern_return_t err;
    vm_address_t page_start = (vm_address_t)target & ~(PAGE_SIZE - 1);
    err = vm_protect(mach_task_self(), page_start, PAGE_SIZE, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (err != KERN_SUCCESS) return;
    *target = replacement;
}

static void rebind_data_symbols(const struct mach_header *header, intptr_t slide, struct rebind_entry *rebinds, size_t nrebinds) {
    segment_command_t *cur_seg_cmd;
    segment_command_t *linkedit_segment = NULL;
    struct symtab_command* symtab_cmd = NULL;
    struct dysymtab_command* dysymtab_cmd = NULL;
    
    cur_seg_cmd = (segment_command_t *)((uintptr_t)header + sizeof(mach_header_t));
    for (uint i = 0; i < header->ncmds; i++, cur_seg_cmd = (segment_command_t *)((uintptr_t)cur_seg_cmd + cur_seg_cmd->cmdsize)) {
        if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            if (strcmp(cur_seg_cmd->segname, "__LINKEDIT") == 0) linkedit_segment = cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) symtab_cmd = (struct symtab_command*)cur_seg_cmd;
        else if (cur_seg_cmd->cmd == LC_DYSYMTAB) dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
    }
    
    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment || !dysymtab_cmd->nindirectsyms) return;
    
    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);
    
    cur_seg_cmd = (segment_command_t *)((uintptr_t)header + sizeof(mach_header_t));
    for (uint i = 0; i < header->ncmds; i++, cur_seg_cmd = (segment_command_t *)((uintptr_t)cur_seg_cmd + cur_seg_cmd->cmdsize)) {
        if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            if (strcmp(cur_seg_cmd->segname, "__DATA") == 0 ||
                strcmp(cur_seg_cmd->segname, "__DATA_CONST") == 0) {
                
                section_t *sect = (section_t *)((uintptr_t)cur_seg_cmd + sizeof(segment_command_t));
                for (uint j = 0; j < cur_seg_cmd->nsects; j++, sect++) {
                    uint8_t type = sect->flags & SECTION_TYPE;
                    if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS) {
                        uint32_t *indirect_symbol_indices = indirect_symtab + sect->reserved1;
                        void **indirect_symbol_bindings = (void **)((uintptr_t)slide + sect->addr);
                        for (uint k = 0; k < sect->size / sizeof(void *); k++) {
                            uint32_t symtab_index = indirect_symbol_indices[k];
                            if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
                                symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
                            uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
                            char *symbol_name = strtab + strtab_offset;
                            bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
                            for (uint l = 0; l < nrebinds; l++) {
                                if (symbol_name_longer_than_1 && strcmp(&symbol_name[1], rebinds[l].name) == 0) {
                                    if (rebinds[l].replaced != NULL && indirect_symbol_bindings[k] != rebinds[l].replacement) {
                                        *(rebinds[l].replaced) = indirect_symbol_bindings[k];
                                    }
                                    safe_write_pointer(&indirect_symbol_bindings[k], rebinds[l].replacement);
                                    goto symbol_loop;
                                }
                            }
                        symbol_loop:;
                        }
                    }
                }
            }
        }
    }
}

// ----------------------------------------------------------------
// 🛡️ C Hook 函数集
// ----------------------------------------------------------------
static CFStringRef (*orig_CFBundleGetIdentifier)(CFBundleRef bundle);
static FILE *(*orig_fopen)(const char *path, const char *mode); // 新增

// 1. Hook CFBundleGetIdentifier
CFStringRef new_CFBundleGetIdentifier(CFBundleRef bundle) {
    if (bundle == CFBundleGetMainBundle()) {
        return (__bridge CFStringRef)kTargetBundleID;
    }
    if (orig_CFBundleGetIdentifier) return orig_CFBundleGetIdentifier(bundle);
    return NULL;
}

// 2. Hook fopen (IO 检测的核心)
FILE *new_fopen(const char *path, const char *mode) {
    if (path) {
        // 如果正在尝试打开 Info.plist
        if (strstr(path, "Info.plist")) {
            NSLog(@"[Stealth] 🕵️‍♂️ 拦截到 fopen 读取 Info.plist: %s", path);
            
            // 如果我们已经准备好了假的 plist 文件，就重定向过去
            if (gFakePlistPath) {
                NSLog(@"[Stealth] ↪️ 重定向到伪造文件: %@", gFakePlistPath);
                return orig_fopen([gFakePlistPath UTF8String], mode);
            }
        }
    }
    return orig_fopen(path, mode);
}

@implementation NSBundle (Stealth)

// ----------------------------------------------------------------
// ⚡️ 核心入口
// ----------------------------------------------------------------
+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        // 1. 震动反馈
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
            NSLog(@"[Stealth] ⚡️ 震动触发");
        });

        // 2. 主线程部署
        dispatch_async(dispatch_get_main_queue(), ^{
            NSLog(@"[Stealth] 🚀 主线程启动...");
            
            // 0. 准备工作：生成假的 Info.plist 文件 (为 fopen 重定向做准备)
            [self prepareFakeInfoPlist];
            
            // A. OC Swizzle (新增了 NSDictionary 的 Hook)
            [self swizzleInstanceMethod:@selector(bundleIdentifier) with:@selector(hook_bundleIdentifier)];
            [self swizzleInstanceMethod:@selector(infoDictionary) with:@selector(hook_infoDictionary)];
            
            // 针对 NSDictionary 的 IO 读取进行拦截
            [self swizzleClassMethod:[NSDictionary class] original:@selector(dictionaryWithContentsOfFile:) new:@selector(hook_dictionaryWithContentsOfFile:)];
            [self swizzleInstanceMethod:[NSDictionary class] original:@selector(initWithContentsOfFile:) new:@selector(hook_initWithContentsOfFile:)];
            
            // B. C Hook (新增 fopen)
            struct rebind_entry rebinds[] = {
                {"CFBundleGetIdentifier", (void *)new_CFBundleGetIdentifier, (void **)&orig_CFBundleGetIdentifier},
                {"fopen", (void *)new_fopen, (void **)&orig_fopen}
            };
            
            const struct mach_header *header = _dyld_get_image_header(0);
            intptr_t slide = _dyld_get_image_vmaddr_slide(0);
            if (header) {
                rebind_data_symbols(header, slide, rebinds, 2);
                NSLog(@"[Stealth] ✅ Fishhook (CAPI + IO) 已执行");
            }
        });
    });
}

// ----------------------------------------------------------------
// 🛠 辅助工具：生成假的 Info.plist
// ----------------------------------------------------------------
+ (void)prepareFakeInfoPlist {
    // 读取原始 Info.plist
    NSString *bundlePath = [[NSBundle mainBundle] pathForResource:@"Info" ofType:@"plist"];
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:bundlePath];
    
    if (dict) {
        // 修改 BundleID
        dict[@"CFBundleIdentifier"] = kTargetBundleID;
        
        // 将修改后的字典写入临时目录
        NSString *tempDir = NSTemporaryDirectory();
        gFakePlistPath = [tempDir stringByAppendingPathComponent:@"FakeInfo.plist"];
        
        [dict writeToFile:gFakePlistPath atomically:YES];
        NSLog(@"[Stealth] 📝 伪造的 Info.plist 已生成: %@", gFakePlistPath);
    }
}

// ----------------------------------------------------------------
// 🛠 Swizzle 工具函数 (区分 Class 和 Instance)
// ----------------------------------------------------------------
+ (void)swizzleInstanceMethod:(Class)cls original:(SEL)originalSel new:(SEL)newSel {
    Method originalMethod = class_getInstanceMethod(cls, originalSel);
    Method newMethod = class_getInstanceMethod(cls, newSel);
    if (class_addMethod(cls, originalSel, method_getImplementation(newMethod), method_getTypeEncoding(newMethod))) {
        class_replaceMethod(cls, newSel, method_getImplementation(originalMethod), method_getTypeEncoding(originalMethod));
    } else {
        method_exchangeImplementations(originalMethod, newMethod);
    }
}

+ (void)swizzleInstanceMethod:(SEL)originalSel with:(SEL)newSel {
    [self swizzleInstanceMethod:[self class] original:originalSel new:newSel];
}

+ (void)swizzleClassMethod:(Class)cls original:(SEL)originalSel new:(SEL)newSel {
    Method originalMethod = class_getClassMethod(cls, originalSel);
    Method newMethod = class_getClassMethod(cls, newSel);
    method_exchangeImplementations(originalMethod, newMethod);
}

// ----------------------------------------------------------------
// 🛡️ OC Hooks (新增 NSDictionary)
// ----------------------------------------------------------------

- (NSString *)hook_bundleIdentifier { return kTargetBundleID; }

- (NSDictionary *)hook_infoDictionary {
    NSDictionary *originalDict = [self hook_infoDictionary];
    if (originalDict && [originalDict isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *newDict = [originalDict mutableCopy];
        newDict[@"CFBundleIdentifier"] = kTargetBundleID;
        return newDict;
    }
    return originalDict;
}

@end

// ----------------------------------------------------------------
// 🛡️ NSDictionary Hook 实现 (放在新的 Category 里避免混乱)
// ----------------------------------------------------------------
@implementation NSDictionary (StealthIO)

// 类方法 Hook
+ (NSDictionary *)hook_dictionaryWithContentsOfFile:(NSString *)path {
    // 如果是读取 Info.plist，直接返回我们内存中生成的伪装字典
    // 或者重定向到假文件路径 (这里直接读假文件更方便)
    if ([path hasSuffix:@"Info.plist"] && gFakePlistPath) {
        return [self hook_dictionaryWithContentsOfFile:gFakePlistPath];
    }
    return [self hook_dictionaryWithContentsOfFile:path];
}

// 实例方法 Hook
- (instancetype)hook_initWithContentsOfFile:(NSString *)path {
    if ([path hasSuffix:@"Info.plist"] && gFakePlistPath) {
        return [self hook_initWithContentsOfFile:gFakePlistPath];
    }
    return [self hook_initWithContentsOfFile:path];
}

@end
