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

// 全局变量：存储伪造的 Info.plist 路径
static NSString *gFakePlistPath = nil;

// ----------------------------------------------------------------
// 🐟 核心引擎：你提供的验证成功的 Fishhook 代码
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

// 🛡️ 安全写入函数 (基于你提供的代码)
static void safe_write_pointer(void **target, void *replacement) {
    kern_return_t err;
    vm_address_t page_start = (vm_address_t)target & ~(PAGE_SIZE - 1);
    
    // 强制赋予 读+写+拷贝 权限 (这是改写 __DATA_CONST 的关键)
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
            
            // 🟢 恢复扫描 __DATA_CONST (这是让 C API 生效的关键)
            if (strcmp(cur_seg_cmd->segname, "__DATA") == 0 ||
                strcmp(cur_seg_cmd->segname, "__DATA_CONST") == 0) {
                
                section_t *sect = (section_t *)((uintptr_t)cur_seg_cmd + sizeof(segment_command_t));
                for (uint j = 0; j < cur_seg_cmd->nsects; j++, sect++) {
                    
                    uint8_t type = sect->flags & SECTION_TYPE;
                    // 处理 Lazy 和 Non-Lazy
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
                                    // 安全写入
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
static FILE *(*orig_fopen)(const char *path, const char *mode);

// 1. Hook C BundleID (攻克第2项)
CFStringRef new_CFBundleGetIdentifier(CFBundleRef bundle) {
    if (bundle == CFBundleGetMainBundle()) {
        return (__bridge CFStringRef)kTargetBundleID;
    }
    if (orig_CFBundleGetIdentifier) return orig_CFBundleGetIdentifier(bundle);
    return NULL;
}

// 2. Hook fopen (攻克第4项)
FILE *new_fopen(const char *path, const char *mode) {
    // 拦截读取 Info.plist 的操作，重定向到假文件
    if (path && strstr(path, "Info.plist") && gFakePlistPath) {
        return orig_fopen([gFakePlistPath UTF8String], mode);
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
            
            // 0. 准备假文件 (为了攻克 IO)
            [self prepareFakeInfoPlist];
            
            // A. OC Swizzle (攻克第1项 + 第3项)
            // 基础 BundleID 拦截
            [self swizzleInstanceMethod:@selector(bundleIdentifier) with:@selector(hook_bundleIdentifier)];
            // 字典拦截 (防止其他 API 读取)
            [self swizzleInstanceMethod:@selector(infoDictionary) with:@selector(hook_infoDictionary)];
            // 关键：路径劫持 (攻克第3项的核心)
            [self swizzleInstanceMethod:@selector(pathForResource:ofType:) with:@selector(hook_pathForResource:ofType:)];
            
            // B. C Hook (攻克第2项 + 第4项)
            struct rebind_entry rebinds[] = {
                {"CFBundleGetIdentifier", (void *)new_CFBundleGetIdentifier, (void **)&orig_CFBundleGetIdentifier},
                {"fopen", (void *)new_fopen, (void **)&orig_fopen}
            };
            
            const struct mach_header *header = _dyld_get_image_header(0);
            intptr_t slide = _dyld_get_image_vmaddr_slide(0);
            if (header) {
                // 使用你提供的、扫描 __DATA_CONST 的 Fishhook 逻辑
                rebind_data_symbols(header, slide, rebinds, 2);
                NSLog(@"[Stealth] ✅ 全能拦截 (CAPI+IO+OC) 已部署");
            }
        });
    });
}

// ----------------------------------------------------------------
// 🛠 辅助工具
// ----------------------------------------------------------------
+ (void)prepareFakeInfoPlist {
    // 读取原始 Info.plist
    NSString *bundlePath = [[NSBundle mainBundle] pathForResource:@"Info" ofType:@"plist"];
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:bundlePath];
    if (dict) {
        // 修改 ID
        dict[@"CFBundleIdentifier"] = kTargetBundleID;
        // 生成假文件到临时目录
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

// 关键：拦截路径查询 (第3项)
- (NSString *)hook_pathForResource:(NSString *)name ofType:(NSString *)ext {
    if ([name isEqualToString:@"Info"] && [ext isEqualToString:@"plist"]) {
        if (gFakePlistPath) return gFakePlistPath;
    }
    return [self hook_pathForResource:name ofType:ext];
}

@end
