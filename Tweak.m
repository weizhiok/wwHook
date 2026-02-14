#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>

// =======================================================
// ⚙️ 配置区域：修改为你想要伪装成的 ID
// =======================================================
static NSString * const kTargetBundleID = @"com.user.bundlechecker";
// =======================================================

// ----------------------------------------------------------------
// 🧩 Fishhook Mini Implementation
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

static void rebind_symbols_image(const struct mach_header *header,
                                 intptr_t slide,
                                 struct rebind_entry *rebinds,
                                 size_t nrebinds) {
    Dl_info info;
    if (dladdr(header, &info) == 0) return;

    segment_command_t *cur_seg_cmd;
    segment_command_t *linkedit_segment = NULL;
    struct symtab_command* symtab_cmd = NULL;
    struct dysymtab_command* dysymtab_cmd = NULL;

    cur_seg_cmd = (segment_command_t *)((uintptr_t)header + sizeof(mach_header_t));
    for (uint i = 0; i < header->ncmds; i++, cur_seg_cmd = (segment_command_t *)((uintptr_t)cur_seg_cmd + cur_seg_cmd->cmdsize)) {
        if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            if (strcmp(cur_seg_cmd->segname, "__LINKEDIT") == 0) {
                linkedit_segment = cur_seg_cmd;
            }
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command*)cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
        }
    }

    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment || !dysymtab_cmd->nindirectsyms) return;

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur_seg_cmd = (segment_command_t *)((uintptr_t)header + sizeof(mach_header_t));
    for (uint i = 0; i < header->ncmds; i++, cur_seg_cmd = (segment_command_t *)((uintptr_t)cur_seg_cmd + cur_seg_cmd->cmdsize)) {
        if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT && strcmp(cur_seg_cmd->segname, "__DATA") == 0) {
            section_t *sect = (section_t *)((uintptr_t)cur_seg_cmd + sizeof(segment_command_t));
            for (uint j = 0; j < cur_seg_cmd->nsects; j++, sect++) {
                if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS || (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                    uint32_t *indirect_symbol_indices = indirect_symtab + sect->reserved1;
                    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + sect->addr);
                    for (uint k = 0; k < sect->size / sizeof(void *); k++) {
                        uint32_t symtab_index = indirect_symbol_indices[k];
                        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL || symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
                        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
                        char *symbol_name = strtab + strtab_offset;
                        if (strtab_offset == 0 || symbol_name[0] == '\0') continue;
                        
                        bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
                        for (uint l = 0; l < nrebinds; l++) {
                            if (symbol_name_longer_than_1 && strcmp(&symbol_name[1], rebinds[l].name) == 0) {
                                if (rebinds[l].replaced != NULL && indirect_symbol_bindings[k] != rebinds[l].replacement) {
                                    *(rebinds[l].replaced) = indirect_symbol_bindings[k];
                                }
                                indirect_symbol_bindings[k] = rebinds[l].replacement;
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

static void rebind_symbols(struct rebind_entry *rebinds, size_t nrebinds) {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
        rebind_symbols_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i), rebinds, nrebinds);
    }
}

// ----------------------------------------------------------------
// 🕵️‍♂️ 原始函数指针保存
// ----------------------------------------------------------------
static CFStringRef (*orig_CFBundleGetIdentifier)(CFBundleRef bundle);
static CFTypeRef (*orig_SecTaskCopyValueForEntitlement)(id task, CFStringRef entitlement, CFErrorRef *error);
static CFStringRef (*orig_SecTaskCopySigningIdentifier)(id task, CFErrorRef *error);
static int (*orig_dladdr)(const void *, Dl_info *);

// ----------------------------------------------------------------
// 🛡️ C Hook 实现
// ----------------------------------------------------------------

CFStringRef new_CFBundleGetIdentifier(CFBundleRef bundle) {
    if (bundle == CFBundleGetMainBundle()) {
        return (__bridge CFStringRef)kTargetBundleID;
    }
    return orig_CFBundleGetIdentifier(bundle);
}

CFTypeRef new_SecTaskCopyValueForEntitlement(id task, CFStringRef entitlement, CFErrorRef *error) {
    if (CFStringCompare(entitlement, CFSTR("application-identifier"), 0) == kCFCompareEqualTo) {
        return (__bridge CFTypeRef)[NSString stringWithFormat:@"ABCDE12345.%@", kTargetBundleID];
    }
    return orig_SecTaskCopyValueForEntitlement(task, entitlement, error);
}

CFStringRef new_SecTaskCopySigningIdentifier(id task, CFErrorRef *error) {
    return (__bridge CFStringRef)kTargetBundleID;
}

// 核心修复点：dladdr 欺骗
int new_dladdr(const void *addr, Dl_info *info) {
    int result = orig_dladdr(addr, info);
    
    if (result != 0 && info) {
        NSString *fname = [NSString stringWithUTF8String:info->dli_fname];
        // 如果检测代码发现了我们
        if ([fname containsString:@"StealthBundleID"] || [fname containsString:@"BundleChecker"]) {
             // 🟢 修复：添加 (__bridge const void *) 进行转换
            Dl_info sysInfo;
            if (orig_dladdr((__bridge const void *)objc_getClass("NSString"), &sysInfo)) {
                info->dli_fname = sysInfo.dli_fname;
                info->dli_sname = "CFStringCreateWithCString";
            }
        }
    }
    return result;
}

// ----------------------------------------------------------------
// 🛡️ OC Swizzle 实现
// ----------------------------------------------------------------
@implementation NSBundle (Stealth)

- (NSString *)stealth_bundleIdentifier {
    return kTargetBundleID;
}

- (NSDictionary *)stealth_infoDictionary {
    NSMutableDictionary *dict = [[self stealth_infoDictionary] mutableCopy];
    if (dict) {
        dict[@"CFBundleIdentifier"] = kTargetBundleID;
    }
    return dict;
}

- (id)stealth_objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kTargetBundleID;
    }
    return [self stealth_objectForInfoDictionaryKey:key];
}

@end

// ----------------------------------------------------------------
// 🚀 启动入口
// ----------------------------------------------------------------
__attribute__((constructor)) static void Initializer() {
    // 1. OC Swizzle
    Method orig = class_getInstanceMethod([NSBundle class], @selector(bundleIdentifier));
    Method hook = class_getInstanceMethod([NSBundle class], @selector(stealth_bundleIdentifier));
    method_exchangeImplementations(orig, hook);
    
    Method origInfo = class_getInstanceMethod([NSBundle class], @selector(infoDictionary));
    Method hookInfo = class_getInstanceMethod([NSBundle class], @selector(stealth_infoDictionary));
    method_exchangeImplementations(origInfo, hookInfo);
    
    Method origKey = class_getInstanceMethod([NSBundle class], @selector(objectForInfoDictionaryKey:));
    Method hookKey = class_getInstanceMethod([NSBundle class], @selector(stealth_objectForInfoDictionaryKey:));
    method_exchangeImplementations(origKey, hookKey);

    // 2. C Rebind (Fishhook)
    struct rebind_entry rebinds[] = {
        {"CFBundleGetIdentifier", (void *)new_CFBundleGetIdentifier, (void **)&orig_CFBundleGetIdentifier},
        {"SecTaskCopyValueForEntitlement", (void *)new_SecTaskCopyValueForEntitlement, (void **)&orig_SecTaskCopyValueForEntitlement},
        {"SecTaskCopySigningIdentifier", (void *)new_SecTaskCopySigningIdentifier, (void **)&orig_SecTaskCopySigningIdentifier},
        {"dladdr", (void *)new_dladdr, (void **)&orig_dladdr}
    };
    
    rebind_symbols(rebinds, 4);
    
    NSLog(@"[StealthBundleID] 隐身模式已激活，Target: %@", kTargetBundleID);
}
