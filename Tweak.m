#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AudioToolbox/AudioToolbox.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <objc/runtime.h>

// =======================================================
// ⚙️ 配置：目标假 ID
// =======================================================
static NSString * const kTargetBundleID = @"com.user.bundlechecker";
// =======================================================

static NSString *gFakePlistPath = nil;

// ----------------------------------------------------------------
// 🐟 核心引擎：Fishhook (Lazy + Non-Lazy + vm_protect)
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

// 🛡️ 安全写入 (vm_protect)
static void safe_write_pointer(void **target, void *replacement) {
    kern_return_t err;
    vm_address_t page_start = (vm_address_t)target & ~(PAGE_SIZE - 1);
    err = vm_protect(mach_task_self(), page_start, PAGE_SIZE, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (err != KERN_SUCCESS) return;
    *target = replacement;
    // 写入后尝试恢复权限(可选)，为了防闪退保持可写通常也没事，只要不是__TEXT段
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
            // 扫描 __DATA 和 __DATA_CONST
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
// 🛡️ Hook 函数集
// ----------------------------------------------------------------
static CFStringRef (*orig_CFBundleGetIdentifier)(CFBundleRef bundle);
static FILE *(*orig_fopen)(const char *path, const char *mode);
static CFStringRef (*orig_SecTaskCopySigningIdentifier)(void *task, CFErrorRef *error);
// 🟢 新增：dladdr 原函数
static int (*orig_dladdr)(const void *, Dl_info *);

// 1. C API Hook (第2项)
CFStringRef new_CFBundleGetIdentifier(CFBundleRef bundle) {
    if (bundle == CFBundleGetMainBundle()) return (__bridge CFStringRef)kTargetBundleID;
    if (orig_CFBundleGetIdentifier) return orig_CFBundleGetIdentifier(bundle);
    return NULL;
}

// 2. IO Hook (第4项)
FILE *new_fopen(const char *path, const char *mode) {
    if (path && strstr(path, "Info.plist") && gFakePlistPath) {
        return orig_fopen([gFakePlistPath UTF8String], mode);
    }
    return orig_fopen(path, mode);
}

// 3. SecTask Hook (第5项)
CFStringRef new_SecTaskCopySigningIdentifier(void *task, CFErrorRef *error) {
    return (__bridge CFStringRef)kTargetBundleID;
}

// 4. 🟢 新增：dladdr Hook (第8项 - 反Swizzle检测)
// 这是骗过“Runtime Swizzle 检测”的核心！
int new_dladdr(const void *addr, Dl_info *info) {
    // 先调用原函数获取真实信息
    int result = orig_dladdr(addr, info);
    
    if (result && info && info->dli_sname) {
        // 检查：如果这个地址是我们的 Hook 函数 (名字里包含 hook_ 或者 new_)
        // 或者简单点，如果它属于我们的 dylib (dli_fname 不是系统路径)
        const char *name = info->dli_sname;
        
        // 如果检测代码查到了我们的 Swizzle 方法
        if (strstr(name, "hook_bundleIdentifier") || 
            strstr(name, "hook_infoDictionary") || 
            strstr(name, "hook_pathForResource")) {
            
            NSLog(@"[Stealth] 🕵️‍♂️ 拦截到 Swizzle 检测 (dladdr): %s", name);
            
            // 欺诈开始：我们需要伪造一个 Foundation 的身份
            // 获取一个真正的系统函数地址，比如 NSBundle 的类对象
            Dl_info fakeInfo;
            if (orig_dladdr((__bridge const void *)[NSBundle class], &fakeInfo)) {
                // 将我们的函数伪装成 Foundation 里的函数
                info->dli_fname = fakeInfo.dli_fname; // "/System/Library/Frameworks/Foundation.framework/..."
                info->dli_fbase = fakeInfo.dli_fbase;
                
                // 把名字改回原本的样子 (去掉 hook_ 前缀)
                if (strstr(name, "hook_bundleIdentifier")) info->dli_sname = "bundleIdentifier";
                else if (strstr(name, "hook_infoDictionary")) info->dli_sname = "infoDictionary";
                else if (strstr(name, "hook_pathForResource")) info->dli_sname = "pathForResource:ofType:";
            }
        }
    }
    return result;
}

@implementation NSBundle (Stealth)

// ----------------------------------------------------------------
// ⚡️ 核心入口
// ----------------------------------------------------------------
+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            AudioServicesPlaySystemSound(kSystemSoundID_Vibrate);
            NSLog(@"[Stealth] ⚡️ 震动触发");
        });

        dispatch_async(dispatch_get_main_queue(), ^{
            NSLog(@"[Stealth] 🚀 主线程启动...");
            
            // 0. IO 准备
            [self prepareFakeInfoPlist];
            
            // A. OC Swizzle (攻克 1, 3)
            [self swizzleInstanceMethod:@selector(bundleIdentifier) with:@selector(hook_bundleIdentifier)];
            [self swizzleInstanceMethod:@selector(infoDictionary) with:@selector(hook_infoDictionary)];
            [self swizzleInstanceMethod:@selector(pathForResource:ofType:) with:@selector(hook_pathForResource:ofType:)];
            
            // B. Fishhook (攻克 2, 4, 5, 8)
            struct rebind_entry rebinds[] = {
                {"CFBundleGetIdentifier", (void *)new_CFBundleGetIdentifier, (void **)&orig_CFBundleGetIdentifier},
                {"fopen", (void *)new_fopen, (void **)&orig_fopen},
                {"SecTaskCopySigningIdentifier", (void *)new_SecTaskCopySigningIdentifier, (void **)&orig_SecTaskCopySigningIdentifier},
                // 🟢 新增：拦截 dladdr
                {"dladdr", (void *)new_dladdr, (void **)&orig_dladdr}
            };
            
            const struct mach_header *header = _dyld_get_image_header(0);
            intptr_t slide = _dyld_get_image_vmaddr_slide(0);
            if (header) {
                rebind_data_symbols(header, slide, rebinds, 4);
                NSLog(@"[Stealth] ✅ 六项全能 (含反Swizzle检测) 已部署");
            }
        });
    });
}

// ----------------------------------------------------------------
// 🛠 辅助工具
// ----------------------------------------------------------------
+ (void)prepareFakeInfoPlist {
    NSString *bundlePath = [[NSBundle mainBundle] pathForResource:@"Info" ofType:@"plist"];
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:bundlePath];
    if (dict) {
        dict[@"CFBundleIdentifier"] = kTargetBundleID;
        NSString *tempDir = NSTemporaryDirectory();
        gFakePlistPath = [tempDir stringByAppendingPathComponent:@"FakeInfo.plist"];
        [dict writeToFile:gFakePlistPath atomically:YES];
    }
}

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
// 🛡️ OC Hooks
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

- (NSString *)hook_pathForResource:(NSString *)name ofType:(NSString *)ext {
    if ([name isEqualToString:@"Info"] && [ext isEqualToString:@"plist"]) {
        if (gFakePlistPath) return gFakePlistPath;
    }
    return [self hook_pathForResource:name ofType:ext];
}

@end
