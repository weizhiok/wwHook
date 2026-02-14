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

// ----------------------------------------------------------------
// 🐟 安全版 Fishhook (只改 Lazy，绝不碰 Non-Lazy)
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

// 🛡️ 安全写入 (保留，用于写入 Lazy 表)
static void safe_write_pointer(void **target, void *replacement) {
    kern_return_t err;
    vm_address_t page_start = (vm_address_t)target & ~(PAGE_SIZE - 1);
    err = vm_protect(mach_task_self(), page_start, PAGE_SIZE, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (err != KERN_SUCCESS) return;
    *target = replacement;
}

static void rebind_lazy_symbols(const struct mach_header *header, intptr_t slide, struct rebind_entry *rebinds, size_t nrebinds) {
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
            
            // 🟢 只扫描 __DATA
            if (strcmp(cur_seg_cmd->segname, "__DATA") == 0) {
                section_t *sect = (section_t *)((uintptr_t)cur_seg_cmd + sizeof(segment_command_t));
                for (uint j = 0; j < cur_seg_cmd->nsects; j++, sect++) {
                    
                    // 🟢 绝对不碰 S_NON_LAZY_SYMBOL_POINTERS (那是闪退之源)
                    // 只处理 S_LAZY_SYMBOL_POINTERS
                    if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
                        
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
// 🛡️ C Hook 函数
// ----------------------------------------------------------------
static CFStringRef (*orig_CFBundleGetIdentifier)(CFBundleRef bundle);
static void* (*orig_dlsym)(void * __handle, const char * __symbol);

// 1. 我们的假 BundleID 获取函数
CFStringRef new_CFBundleGetIdentifier(CFBundleRef bundle) {
    // 只要是查主包，就给假的
    if (bundle == CFBundleGetMainBundle()) {
        return (__bridge CFStringRef)kTargetBundleID;
    }
    // 为了防止递归或空指针，尽量不调 orig，直接返回 NULL 让系统处理，或者硬着头皮调
    // 简单起见，这里假设我们只关心主包
    if (orig_CFBundleGetIdentifier) return orig_CFBundleGetIdentifier(bundle);
    return NULL;
}

// 2. 🟢 核心大招：拦截 dlsym
// 如果检测工具试图通过 dlsym(RTLD_DEFAULT, "CFBundleGetIdentifier") 来绕过我们
// 我们就拦截 dlsym，直接把假函数的地址给它！
void* new_dlsym(void * __handle, const char * __symbol) {
    if (__symbol && strcmp(__symbol, "CFBundleGetIdentifier") == 0) {
        NSLog(@"[Stealth] 🕵️‍♂️ 拦截到 dlsym 查询 CFBundleGetIdentifier，返回假地址！");
        return (void *)new_CFBundleGetIdentifier;
    }
    if (orig_dlsym) {
        return orig_dlsym(__handle, __symbol);
    }
    return NULL;
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
        });

        // 2. 主线程部署
        dispatch_async(dispatch_get_main_queue(), ^{
            NSLog(@"[Stealth] 🚀 主线程启动...");
            
            // A. OC Swizzle (Ivar + Method, 保持不变，这是防线基础)
            [self injectModifiedDictionary];
            [self swizzleInstanceMethod:@selector(bundleIdentifier) with:@selector(hook_bundleIdentifier)];
            
            // B. C Hook (Lazy Only + dlsym)
            struct rebind_entry rebinds[] = {
                // Hook CFBundleGetIdentifier (如果它是懒加载的)
                {"CFBundleGetIdentifier", (void *)new_CFBundleGetIdentifier, (void **)&orig_CFBundleGetIdentifier},
                // Hook dlsym (防止动态查询绕过)
                {"dlsym", (void *)new_dlsym, (void **)&orig_dlsym}
            };
            
            // C. 仅对主程序执行 Hook
            const struct mach_header *header = _dyld_get_image_header(0);
            intptr_t slide = _dyld_get_image_vmaddr_slide(0);
            if (header) {
                // 只扫描懒加载表！绝对不碰非懒加载表！(防闪退)
                rebind_lazy_symbols(header, slide, rebinds, 2);
                NSLog(@"[Stealth] ✅ 懒加载表 Hook + dlsym 拦截已部署");
            }
        });
    });
}

// ----------------------------------------------------------------
// 🛠 OC Hooks
// ----------------------------------------------------------------
+ (void)injectModifiedDictionary {
    NSBundle *mainBundle = [NSBundle mainBundle];
    NSDictionary *originalDict = [mainBundle infoDictionary];
    if (originalDict) {
        NSMutableDictionary *newDict = [originalDict mutableCopy];
        newDict[@"CFBundleIdentifier"] = kTargetBundleID;
        Ivar ivar = class_getInstanceVariable([NSBundle class], "_infoDictionary");
        if (ivar) object_setIvar(mainBundle, ivar, newDict);
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

- (NSString *)hook_bundleIdentifier { return kTargetBundleID; }

@end
