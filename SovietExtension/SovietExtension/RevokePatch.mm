//
//  RevokePatch.mm
//  SovietExtension
//
//  Created by MustangYM on 2026/6/12.
//
//  但我还是想说, 开源共产主义, 爱你们
//         -- MustangYM 2026-6-16
//0x11ffac000
#import "RevokePatch.h"
#import "AntiUpdate.h"
#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <libkern/OSCacheControl.h>
#import <unistd.h>
#import <string.h>
#import <stdint.h>
#import <stdarg.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "MenuManager.h"
#import "NSObject+MainHook.h"

#include <string>
#include <time.h>
#include <atomic>

#pragma mark - 全局状态

static BOOL YMHasPatchedAntiRevoke = NO;

// 当前 /Applications/WeChat.app/Contents/Resources/wechat.dylib 的 ASLR slide。
// dyld 加载 wechat.dylib 后会赋值。
static uintptr_t YMWeChatDylibSlide = 0;

// 多开 Patch 状态
static BOOL YMHasPatchedMultiOpenResourceDylib = NO;
static BOOL YMHasRegisteredDyldCallback = NO;

//static const uintptr_t YMMultiOpenTryPreventMultiInstanceVA = 0x1C0A64;

// 先声明，后面 constructor 和 anti revoke 都会用。
static void YMDyldImageAdded(const struct mach_header *mh, intptr_t vmaddr_slide);
static void YMRegisterDyldCallbackIfNeeded(void);
static void YMInstallMultiOpenPatch(void);

typedef enum {
    YMRevokeHookModePointer = 0,   // 4.1.9：写 off_91EAD20
    YMRevokeHookModeInline  = 1,   // 4.1.10：直接 patch 函数入口
} YMRevokeHookMode;

#pragma mark - MessageWrap 字段布局

/*
 当前版本运行时已经验证：
   rawWrap + 24  = 对方 / 当前聊天会话
   rawWrap + 48  = 当前登录账号 / 自己
   rawWrap + 256 = 毫秒级时间戳
   rawWrap + 276 = 秒级时间戳
   rawWrap + 328 = content / XML
 
 以后适配新版时：
   1. 如果 raw field24 / raw field48 打印正常，一般不用改这里。
   2. 如果打印乱码、空字符串、插错会话，再重新确认这些偏移。
 */
typedef struct {
    size_t messageWrapSize;

    size_t remoteUserOrSessionOffset;
    size_t selfUserOffset;

    size_t createTimeMsOffset;
    size_t createTimeSecOffset;

    size_t contentOffset;
} YMMessageWrapLayout;

#pragma mark - 微信版本适配配置

/*
 当前适配版本：
 CFBundleShortVersionString = 4.1.9
 CFBundleVersion = 268602
 Resources/wechat.dylib arm64

 注意：
 这些都是 IDA/Hopper 里的静态 VM 地址。
 运行时地址 = YMWeChatDylibSlide + 静态地址。
 */
typedef struct {
    const char *displayName;

    const char *bundleID;
    const char *shortVersion;
    const char *buildVersion;

    uintptr_t hookPointerVA;
    uintptr_t rawMessageTemplateVA;
    uintptr_t messageWrapFromRawVA;
    uintptr_t messageWrapDestructVA;
    uintptr_t insertPaySysMsgToSessionVA;
    uintptr_t YMMultiOpenTryPreventMultiInstanceVA;

    YMMessageWrapLayout layout;
    
    YMRevokeHookMode hookMode;//4.1.10添加
} YMWeChatAdaptProfile;

static const YMWeChatAdaptProfile YMAdaptProfiles[] = {
    {
        .displayName = "Mac WeChat 4.1.9.58 arm64 / 268602",

        .bundleID = "com.tencent.xinWeChat",
        .shortVersion = "4.1.9",
        .buildVersion = "268602",

        // ym_HandleSysMsg_RevokeMsg 开头的热补丁函数指针。
        // 汇编：
        //   ADRP X9, #off_91EAD20@PAGE
        //   LDR  X9, [X9,#off_91EAD20@PAGEOFF]
        //   CBZ  X9, loc_27A03B0
        //   BR   X9
        .hookMode = YMRevokeHookModePointer,
        .hookPointerVA = 0x91EAD20, // ym_HandleSysMsg_RevokeMsg->

        // ym_HandleSysMsg_RevokeMsg 原函数里用来构造撤回 MessageWrap 的模板：unk_7861730
        .rawMessageTemplateVA = 0x7861730, // ym_HandleSysMsg_RevokeMsg->

        // MessageWrap 相关函数
        .messageWrapFromRawVA = 0x4728670, // ym_HandleSysMsg_RevokeMsg->
        .messageWrapDestructVA = 0x206F0D0, // ym_HandleSysMsg_RevokeMsg->

        // 现成的本地系统消息插入函数。
        // sub_3822FA4：内部会构造 type=10000 + paymsg XML，然后调用 ym_AddLocalMessageWrap。
        .insertPaySysMsgToSessionVA = 0x3822FA4, // [CDATA]->
        .YMMultiOpenTryPreventMultiInstanceVA = 0x1C0A64,

        .layout = {
            .messageWrapSize = 616,

            .remoteUserOrSessionOffset = 24,
            .selfUserOffset = 48,

            .createTimeMsOffset = 256,
            .createTimeSecOffset = 276,

            .contentOffset = 328,
        },
    },
    
    {
        .displayName = "Mac WeChat 4.1.10.53 arm64 / 268853",

        .bundleID = "com.tencent.xinWeChat",
        .shortVersion = "4.1.10",
        .buildVersion = "268853",

        // ym_HandleSysMsg_RevokeMsg 开头的热补丁函数指针。
        // 汇编：
        //   ADRP X9, #off_91EAD20@PAGE
        //   LDR  X9, [X9,#off_91EAD20@PAGEOFF]
        //   CBZ  X9, loc_27A03B0
        //   BR   X9
        .hookMode = YMRevokeHookModeInline,
        .hookPointerVA = 0x2846E84, // ym_HandleSysMsg_RevokeMsg->

        // ym_HandleSysMsg_RevokeMsg 原函数里用来构造撤回 MessageWrap 的模板：unk_7861730
        .rawMessageTemplateVA = 0x7A7AD88, // ym_HandleSysMsg_RevokeMsg->

        // MessageWrap 相关函数
        .messageWrapFromRawVA = 0x482F54C, // ym_HandleSysMsg_RevokeMsg->
        .messageWrapDestructVA = 0x2123AC0, // ym_HandleSysMsg_RevokeMsg->

        // 现成的本地系统消息插入函数。
        // sub_3822FA4：内部会构造 type=10000 + paymsg XML，然后调用 ym_AddLocalMessageWrap。
        .insertPaySysMsgToSessionVA = 0x38EBBFC, // [CDATA]->
        .YMMultiOpenTryPreventMultiInstanceVA = 0x1C4EA8,

        .layout = {
            .messageWrapSize = 616,

            .remoteUserOrSessionOffset = 24,
            .selfUserOffset = 48,

            .createTimeMsOffset = 256,
            .createTimeSecOffset = 276,

            .contentOffset = 328,
        },
    },

    /*
     新版适配示例代码:

     {
         .displayName = "Mac WeChat 4.1.10 arm64 / xxxxxx",

         .bundleID = "com.tencent.xinWeChat",
         .shortVersion = "4.1.10",
         .buildVersion = "新版 CFBundleVersion",

         .hookPointerVA = 新版地址,
         .rawMessageTemplateVA = 新版地址,
         .messageWrapFromRawVA = 新版地址,
         .messageWrapDestructVA = 新版地址,
         .insertPaySysMsgToSessionVA = 新版地址,

         .layout = {
             .messageWrapSize = 616,

             .remoteUserOrSessionOffset = 24,
             .selfUserOffset = 48,

             .createTimeMsOffset = 256,
             .createTimeSecOffset = 276,

             .contentOffset = 328,
         },
     },
     */
};

static const size_t YMAdaptProfilesCount = sizeof(YMAdaptProfiles) / sizeof(YMAdaptProfiles[0]);

// 当前运行版本匹配到的配置。
// 后面所有地址都从这里取，不再写死单个 YMCurrentProfile。
static const YMWeChatAdaptProfile *YMActiveProfile = NULL;

#pragma mark - 微信内部函数类型

typedef void (*YMMessageWrapFromRawFunc)(void *message, int64_t rawMessage);
typedef void (*YMMessageWrapDestructFunc)(int64_t message);

typedef int64_t (*YMInsertPaySysMsgToSessionFunc)(int64_t a1,
                                                  const std::string *session,
                                                  const std::string *content);

/*
 paymsg / red_envelope 反编译里表现为：
   ym_AddLocalMessageWrap(v39[0], v32);

 所以这里按两个参数声明：
   messageService = v39[0]
   message        = MessageWrap*
 */
typedef int64_t (*YMAddLocalMessageWrapFunc)(int64_t messageService, void *message);

#pragma mark - 日志

void YMLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSLog(@"[YMAntiRevoke] %@", msg);

    NSString *line = [NSString stringWithFormat:@"%@\n", msg];
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    NSString *path = @"/tmp/YMWeChatAntiRevokePatch.log";

    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [data writeToFile:path atomically:YES];
    } else {
        [fh seekToEndOfFile];
        [fh writeData:data];
        [fh closeFile];
    }
}

#pragma mark - 字符串辅助

static NSString *YMNSStringFromCString(const char *cString) {
    if (!cString) {
        return @"";
    }

    return [NSString stringWithUTF8String:cString] ?: @"";
}

static std::string YMStdStringFromNSString(NSString *text) {
    if (!text) {
        return std::string();
    }

    const char *utf8 = [text UTF8String];
    if (!utf8) {
        return std::string();
    }

    return std::string(utf8);
}

static NSString *YMNSStringFromStdString(const std::string *value) {
    if (!value) {
        return @"";
    }

    const char *cString = NULL;

    try {
        cString = value->c_str();
    } catch (...) {
        return @"";
    }

    if (!cString) {
        return @"";
    }

    return [NSString stringWithUTF8String:cString] ?: @"";
}

#pragma mark - Profile 匹配

static BOOL YMProfileHasValidAddresses(const YMWeChatAdaptProfile *profile) {
    if (!profile) {
        return NO;
    }

    return profile->hookPointerVA != 0 &&
           profile->rawMessageTemplateVA != 0 &&
           profile->messageWrapFromRawVA != 0 &&
           profile->messageWrapDestructVA != 0 &&
           profile->insertPaySysMsgToSessionVA != 0 &&
           profile->layout.messageWrapSize > 0;
}

static const YMWeChatAdaptProfile *YMFindAdaptProfileForCurrentWeChat(void) {
    NSBundle *bundle = [NSBundle mainBundle];

    NSString *bundleID = [bundle bundleIdentifier] ?: @"";
    NSString *shortVersion = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    NSString *buildVersion = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";

    YMLog(@"bundleID=%@, version=%@, build=%@", bundleID, shortVersion, buildVersion);

    for (size_t i = 0; i < YMAdaptProfilesCount; i++) {
        const YMWeChatAdaptProfile *profile = &YMAdaptProfiles[i];

        NSString *expectedBundleID = YMNSStringFromCString(profile->bundleID);
        NSString *expectedShortVersion = YMNSStringFromCString(profile->shortVersion);
        NSString *expectedBuildVersion = YMNSStringFromCString(profile->buildVersion);

        if (![bundleID isEqualToString:expectedBundleID]) {
            continue;
        }

        if (![shortVersion isEqualToString:expectedShortVersion]) {
            continue;
        }

        if (![buildVersion isEqualToString:expectedBuildVersion]) {
            continue;
        }

        YMLog(@"matched adapt profile: %s", profile->displayName);

        if (!YMProfileHasValidAddresses(profile)) {
            YMLog(@"matched profile but addresses are incomplete: %s", profile->displayName);
            return NULL;
        }

        return profile;
    }

    YMLog(@"no adapt profile matched current WeChat version");
    return NULL;
}

static const YMWeChatAdaptProfile *YMGetActiveProfile(void) {
    if (YMActiveProfile) {
        return YMActiveProfile;
    }

    YMActiveProfile = YMFindAdaptProfileForCurrentWeChat();
    return YMActiveProfile;
}

#pragma mark - 地址辅助

uintptr_t YMRuntimeAddress(uintptr_t staticVA) {
    if (YMWeChatDylibSlide == 0 || staticVA == 0) {
        return 0;
    }

    return YMWeChatDylibSlide + staticVA;
}

uintptr_t getDylibSlide()
{
    return YMWeChatDylibSlide;
}

static inline void *YMRuntimePointer(uintptr_t staticVA) {
    uintptr_t address = YMRuntimeAddress(staticVA);
    if (address == 0) {
        return NULL;
    }

    return (void *)address;
}

#pragma mark - 版本检查

static BOOL YMIsTargetWeChatVersion(void) {
    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();

    if (!profile) {
        YMLog(@"unsupported WeChat version, skip anti revoke");
        return NO;
    }

    YMLog(@"current adapt profile=%s", profile->displayName);
    return YES;
}

#pragma mark - C++ std::string 辅助

/*
 第一版先默认使用纯文本系统消息。
 老版 WeChatExtension 也是类似逻辑：msgType=10000 + content 文案。
 如果纯文本不显示，再把这里改成 XML 版本测试。
 */
__attribute__((unused))
static std::string YMBuildAntiRevokeSystemContent(void) {
    return YMStdStringFromNSString(@"已拦截到一条撤回消息");
}

/*
 备用 XML 版本。
 如果纯文本版本插入了但 UI 不显示，可以把 YMBuildAntiRevokeSystemContent()
 里 return 改成这个函数。
 */
__attribute__((unused))
static std::string YMBuildAntiRevokeSystemXMLContent(void) {
    std::string text = YMStdStringFromNSString(@"已拦截到一条撤回消息");

    std::string xml;
    xml += "<?xml version=\"1.0\"?>\n";
    xml += "<sysmsg type=\"paymsg\">";
    xml += "<content><![CDATA[";
    xml += text;
    xml += "]]></content>";
    xml += "</sysmsg>";

    return xml;
}

#pragma mark - shared_ptr 释放辅助

/*
 微信内部大量使用 libc++ shared_ptr。
 反编译中一般是：
   if (control && !atomic_fetch_add(control + 8, -1)) {
       control->__on_zero_shared(control);
       std::__shared_weak_count::__release_weak(control);
   }

 这里第一版只用于我们自己栈上临时 shared_ptr 的释放。
 如果测试阶段担心这里有风险，可以临时把调用 YMReleaseSharedPtrStorage 的地方注释掉。
 */
__attribute__((unused))
static void YMReleaseSharedPtrStorage(void *storage) {
    if (!storage) {
        return;
    }

    void **items = (void **)storage;
    void *controlBlock = items[1];

    items[0] = NULL;
    items[1] = NULL;

    if (!controlBlock) {
        return;
    }

    // libc++ shared_count 的 shared_owners_ 通常在 controlBlock + 8。
    volatile long *sharedOwners = (volatile long *)((uint8_t *)controlBlock + 8);
    long oldValue = __atomic_fetch_add(sharedOwners, -1, __ATOMIC_ACQ_REL);

    // 反编译里的判断是 oldValue == 0 时释放。
    if (oldValue == 0) {
        void **vtable = *(void ***)controlBlock;

        // vtable[2] 通常对应 __on_zero_shared()
        if (vtable && vtable[2]) {
            typedef void (*OnZeroSharedFunc)(void *);
            ((OnZeroSharedFunc)vtable[2])(controlBlock);
        }

        // vtable[3] 通常对应 __on_zero_shared_weak()
        if (vtable && vtable[3]) {
            typedef void (*OnZeroSharedWeakFunc)(void *);
            ((OnZeroSharedWeakFunc)vtable[3])(controlBlock);
        }
    }
}

#pragma mark - MessageWrap 字段读取

static std::string *YMRawWrapStringField(void *rawWrap, size_t offset) {
    if (!rawWrap) {
        return NULL;
    }

    return (std::string *)((uint8_t *)rawWrap + offset);
}

static uint32_t YMRawWrapUInt32Field(void *rawWrap, size_t offset) {
    if (!rawWrap) {
        return 0;
    }

    return *(uint32_t *)((uint8_t *)rawWrap + offset);
}

static uint64_t YMRawWrapUInt64Field(void *rawWrap, size_t offset) {
    if (!rawWrap) {
        return 0;
    }

    return *(uint64_t *)((uint8_t *)rawWrap + offset);
}

static NSString *YMFormatTimestamp(uint32_t createTimeSec, uint64_t createTimeMs) {
    NSTimeInterval messageTimestamp = 0;

    if (createTimeSec > 0) {
        messageTimestamp = (NSTimeInterval)createTimeSec;
    } else if (createTimeMs > 0) {
        messageTimestamp = (NSTimeInterval)(createTimeMs / 1000);
    } else {
        messageTimestamp = [[NSDate date] timeIntervalSince1970];
    }

    NSDate *messageDate = [NSDate dateWithTimeIntervalSince1970:messageTimestamp];

    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"zh_CN"];
    formatter.timeZone = [NSTimeZone localTimeZone];
    formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";

    return [formatter stringFromDate:messageDate] ?: @"";
}

static NSString *YMBuildAntiRevokeNoticeText(NSString *remoteUserOrSession,
                                             NSString *selfUser,
                                             NSString *messageTimeText,
                                             int64_t rawRevokeMessage) {
    /*
     这里是最终插入聊天流的灰色提示文案。
     以后如果想精简，可以只保留第一行和消息时间。
     */
    return [NSString stringWithFormat:
            @"⚠️苏维埃已拦截撤回消息⚠️\n撤回方/会话：%@\n%@",
            remoteUserOrSession ?: @"",
            messageTimeText ?: @""
           ];
}

#pragma mark - 内存写入

static BOOL YMWritePointer(uintptr_t address,
                           uintptr_t value,
                           uintptr_t expectedOldValue,
                           const char *name) {
    if (address == 0 || value == 0) {
        YMLog(@"invalid pointer patch argument: %s", name);
        return NO;
    }

    uintptr_t *target = (uintptr_t *)address;
    uintptr_t current = *target;

    if (current == value) {
        YMLog(@"pointer already hooked: %s at 0x%lx", name, (unsigned long)address);
        return YES;
    }

    if (current != expectedOldValue) {
        YMLog(@"pointer old value mismatch: %s", name);
        YMLog(@"address=0x%lx, current=0x%lx, expected=0x%lx, new=0x%lx",
              (unsigned long)address,
              (unsigned long)current,
              (unsigned long)expectedOldValue,
              (unsigned long)value);
        return NO;
    }

    vm_size_t pageSize = (vm_size_t)getpagesize();
    vm_address_t pageStart = (vm_address_t)(address & ~((uintptr_t)pageSize - 1));
    vm_size_t protectSize = pageSize;

    kern_return_t kr = vm_protect(mach_task_self(),
                                  pageStart,
                                  protectSize,
                                  false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

    if (kr != KERN_SUCCESS) {
        YMLog(@"vm_protect pointer RW|COPY failed: %s, kr=%d", name, kr);
        return NO;
    }

    __atomic_store_n(target, value, __ATOMIC_SEQ_CST);

    YMLog(@"pointer hook success: %s, address=0x%lx, value=0x%lx",
          name,
          (unsigned long)address,
          (unsigned long)value);

    return YES;
}

#pragma mark - ARM64 代码段 Patch

static void YMPrintCodeBytes(const char *name, const char *stage, void *address) {
    if (!address) {
        YMLog(@"%s %s address is NULL", name, stage);
        return;
    }

    uint32_t bytes[4] = {0};
    memcpy(bytes, address, sizeof(bytes));

    YMLog(@"%s %s address=%p bytes=%08x %08x %08x %08x",
          name,
          stage,
          address,
          bytes[0],
          bytes[1],
          bytes[2],
          bytes[3]);
}

static BOOL YMProtectCodePage(uintptr_t address,
                              size_t patchSize,
                              vm_prot_t protection,
                              const char *name,
                              const char *stage) {
    vm_size_t pageSize = (vm_size_t)getpagesize();
    vm_address_t pageStart = (vm_address_t)(address & ~((uintptr_t)pageSize - 1));

    uintptr_t patchEnd = address + patchSize;
    uintptr_t pageEnd = (patchEnd + pageSize - 1) & ~((uintptr_t)pageSize - 1);

    vm_size_t protectSize = (vm_size_t)(pageEnd - pageStart);

    kern_return_t kr = vm_protect(mach_task_self(),
                                  pageStart,
                                  protectSize,
                                  false,
                                  protection);

    if (kr != KERN_SUCCESS) {
        YMLog(@"%s vm_protect %s failed, address=0x%lx, pageStart=0x%lx, size=%lu, kr=%d",
              name,
              stage,
              (unsigned long)address,
              (unsigned long)pageStart,
              (unsigned long)protectSize,
              kr);
        return NO;
    }

    return YES;
}

/*
 ARM64 BOOL/int 强制返回 YES：

   mov w0, #1
   ret

 机器码：
   20 00 80 52
   C0 03 5F D6

 注意：
   这里用 w0，不用 x0。
   因为 sub_200730 里是 if (v85 & 1)，本质是 BOOL/int。
 */
static BOOL YMPatchARM64ReturnYES(uintptr_t address, const char *name) {
    if (address == 0) {
        YMLog(@"%s patch failed: address is zero", name);
        return NO;
    }

    void *target = (void *)address;

    uint32_t patch[2] = {
        0x52800020, // mov w0, #1
        0xD65F03C0  // ret
    };

    YMPrintCodeBytes(name, "before", target);

    uint32_t current[2] = {0};
    memcpy(current, target, sizeof(current));

    if (current[0] == patch[0] && current[1] == patch[1]) {
        YMLog(@"%s already patched, address=0x%lx", name, (unsigned long)address);
        return YES;
    }

    if (!YMProtectCodePage(address,
                           sizeof(patch),
                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
                           name,
                           "RW|COPY")) {
        return NO;
    }

    memcpy(target, patch, sizeof(patch));

    /*
     写指令后必须清 i-cache。
     否则 CPU 可能继续执行旧指令。
     */
    sys_icache_invalidate(target, sizeof(patch));

    if (!YMProtectCodePage(address,
                           sizeof(patch),
                           VM_PROT_READ | VM_PROT_EXECUTE,
                           name,
                           "RX")) {
        return NO;
    }

    YMPrintCodeBytes(name, "after", target);

    uint32_t check[2] = {0};
    memcpy(check, target, sizeof(check));

    BOOL ok = check[0] == patch[0] && check[1] == patch[1];

    YMLog(@"%s patch result=%@, address=0x%lx",
          name,
          ok ? @"OK" : @"FAIL",
          (unsigned long)address);

    return ok;
}

/*
 4.1.10
 ARM64 函数入口绝对跳转：

   ldr x16, #8
   br  x16
   .quad hookAddress

 机器码：
   50 00 00 58
   00 02 1F D6
   hookAddress 8 bytes

 说明：
   1. x16 是临时寄存器，按 ABI 可以用。
   2. 不改 x0/x1，所以 YMHandleSysMsgRevokeMsgHook(a1, a2) 能正常收到参数。
   3. 原函数是被 BL 调用的，LR 已经是上层返回地址。
      用 BR 跳到 hook，hook 最后 ret，会直接回到原调用者。
   4. 这里不需要 trampoline，因为就是要阻止原撤回逻辑继续执行。
 */
static BOOL YMPatchARM64AbsoluteJump(uintptr_t address,
                                     uintptr_t targetAddress,
                                     const char *name) {
    if (address == 0 || targetAddress == 0) {
        YMLog(@"%s inline hook failed: address or target is zero", name);
        return NO;
    }

    void *target = (void *)address;

    uint8_t patch[16] = {0};

    uint32_t insnLdrX16 = 0x58000050; // ldr x16, #8
    uint32_t insnBrX16  = 0xD61F0200; // br x16

    memcpy(patch + 0, &insnLdrX16, sizeof(insnLdrX16));
    memcpy(patch + 4, &insnBrX16, sizeof(insnBrX16));
    memcpy(patch + 8, &targetAddress, sizeof(targetAddress));

    YMPrintCodeBytes(name, "before", target);

    uint8_t current[16] = {0};
    memcpy(current, target, sizeof(current));

    if (memcmp(current, patch, sizeof(patch)) == 0) {
        YMLog(@"%s already inline hooked, address=0x%lx",
              name,
              (unsigned long)address);
        return YES;
    }

    if (!YMProtectCodePage(address,
                           sizeof(patch),
                           VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
                           name,
                           "RW|COPY")) {
        return NO;
    }

    memcpy(target, patch, sizeof(patch));

    sys_icache_invalidate(target, sizeof(patch));

    if (!YMProtectCodePage(address,
                           sizeof(patch),
                           VM_PROT_READ | VM_PROT_EXECUTE,
                           name,
                           "RX")) {
        return NO;
    }

    uint8_t check[16] = {0};
    memcpy(check, target, sizeof(check));

    BOOL ok = memcmp(check, patch, sizeof(patch)) == 0;

    YMPrintCodeBytes(name, "after", target);

    YMLog(@"%s inline hook result=%@, address=0x%lx, target=0x%lx",
          name,
          ok ? @"OK" : @"FAIL",
          (unsigned long)address,
          (unsigned long)targetAddress);

    return ok;
}

#pragma mark - 本地插入灰色系统消息

/*
 参数 rawRevokeMessage：
   这是 ym_HandleSysMsg_RevokeMsg 原函数的第二个参数 X1。
   原函数会用 sub_4728670(rawWrap, rawRevokeMessage) 构造一个 MessageWrap。

 我们复用这一步，主要是为了拿到会话相关字段：
   rawWrap + 24
   rawWrap + 48

 然后构造自己的 type=10000 MessageWrap 插入本地聊天流。
 */
static BOOL YMInsertLocalAntiRevokeNotice(int64_t rawRevokeMessage) {
    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();
    if (!profile) {
        YMLog(@"insert local notice failed: no active profile");
        return NO;
    }

    if (YMWeChatDylibSlide == 0) {
        YMLog(@"insert local notice failed: YMWeChatDylibSlide is zero");
        return NO;
    }

    if (rawRevokeMessage == 0) {
        YMLog(@"insert local notice failed: rawRevokeMessage is zero");
        return NO;
    }

    YMLog(@"try insert local anti revoke notice by sub_3822FA4, rawRevokeMessage=0x%llx, profile=%s",
          (unsigned long long)rawRevokeMessage,
          profile->displayName);

    YMMessageWrapFromRawFunc MessageWrapFromRaw =
    (YMMessageWrapFromRawFunc)YMRuntimePointer(profile->messageWrapFromRawVA);

    YMMessageWrapDestructFunc MessageWrapDestruct =
    (YMMessageWrapDestructFunc)YMRuntimePointer(profile->messageWrapDestructVA);

    YMInsertPaySysMsgToSessionFunc InsertPaySysMsgToSession =
    (YMInsertPaySysMsgToSessionFunc)YMRuntimePointer(profile->insertPaySysMsgToSessionVA);

    if (!MessageWrapFromRaw || !MessageWrapDestruct || !InsertPaySysMsgToSession) {
        YMLog(@"insert local notice failed: internal function pointer is null");
        return NO;
    }

    /*
     rawWrap：
     复刻 ym_HandleSysMsg_RevokeMsg 原始逻辑：

       memcpy(rawWrap, unk_7861730, 616)
       sub_4728670(rawWrap, rawRevokeMessage)

     目的：
       只为了从 rawWrap 里拿到会话字段。
    */
    const size_t wrapSize = profile->layout.messageWrapSize;

    alignas(16) uint8_t rawWrap[616];
    memset(rawWrap, 0, sizeof(rawWrap));

    if (wrapSize > sizeof(rawWrap)) {
        YMLog(@"insert local notice failed: wrapSize too large. wrapSize=%zu", wrapSize);
        return NO;
    }

    void *rawTemplate = YMRuntimePointer(profile->rawMessageTemplateVA);
    if (!rawTemplate) {
        YMLog(@"insert local notice failed: rawTemplate is null");
        return NO;
    }

    memcpy(rawWrap, rawTemplate, wrapSize);

    MessageWrapFromRaw(rawWrap, rawRevokeMessage);

    BOOL ok = NO;

    try {
        std::string *rawField24 = YMRawWrapStringField(rawWrap, profile->layout.remoteUserOrSessionOffset);
        std::string *rawField48 = YMRawWrapStringField(rawWrap, profile->layout.selfUserOffset);

        NSString *remoteUserOrSessionText = YMNSStringFromStdString(rawField24);
        NSString *selfUserText = YMNSStringFromStdString(rawField48);

        YMLog(@"raw field24=%s", rawField24 ? rawField24->c_str() : "");
        YMLog(@"raw field48=%s", rawField48 ? rawField48->c_str() : "");

        /*
         从实际测试结果看：
           rawField24 = 对方 / 当前聊天会话
           rawField48 = 当前登录账号 / 自己

         所以这里必须用 rawField24 作为 session。
         */
        std::string *remoteUserOrSession = rawField24;
        std::string *selfUser = rawField48;

        std::string *session = remoteUserOrSession;

        if (!session || session->empty()) {
            YMLog(@"rawField24 is empty, fallback to rawField48");
            session = rawField48;
        }

        if (!session || session->empty()) {
            YMLog(@"insert local notice failed: session is empty");
            MessageWrapDestruct((int64_t)rawWrap);
            return NO;
        }

        uint32_t rawCreateTimeSec = YMRawWrapUInt32Field(rawWrap, profile->layout.createTimeSecOffset);
        uint64_t rawCreateTimeMs  = YMRawWrapUInt64Field(rawWrap, profile->layout.createTimeMsOffset);

        NSString *messageTimeText = YMFormatTimestamp(rawCreateTimeSec, rawCreateTimeMs);

        NSString *noticeText = YMBuildAntiRevokeNoticeText(remoteUserOrSessionText,
                                                           selfUserText,
                                                           messageTimeText,
                                                           rawRevokeMessage);

        std::string content = YMStdStringFromNSString(noticeText);

        YMLog(@"raw createTimeSec=%u", rawCreateTimeSec);
        YMLog(@"raw createTimeMs=%llu", (unsigned long long)rawCreateTimeMs);
        YMLog(@"message time=%@", messageTimeText);

        YMLog(@"insert notice session=%s", session->c_str());
        YMLog(@"insert notice remoteUserOrSession=%s", remoteUserOrSession ? remoteUserOrSession->c_str() : "");
        YMLog(@"insert notice selfUser=%s", selfUser ? selfUser->c_str() : "");
        YMLog(@"insert notice content=%s", content.c_str());
        YMLog(@"call insertPaySysMsgToSession at 0x%lx",
              (unsigned long)YMRuntimeAddress(profile->insertPaySysMsgToSessionVA));

        int64_t result = InsertPaySysMsgToSession(0, session, &content);

        YMLog(@"insertPaySysMsgToSession result=0x%llx", (unsigned long long)result);

        ok = YES;
    } catch (...) {
        YMLog(@"exception while calling insertPaySysMsgToSession insert local notice");
        ok = NO;
    }

    MessageWrapDestruct((int64_t)rawWrap);

    return ok;
}

#pragma mark - 撤回入口 Hook

/*
 这个函数会被 off_91EAD20 热补丁指针调用。

 原函数签名：
   __int64 ym_HandleSysMsg_RevokeMsg(__int64 a1, __int64 a2)

 我们做两件事：
   1. 自己插入一条本地 type=10000 系统消息
   2. return 1，告诉上层这个 sysmsg 已经处理，阻止微信原始撤回逻辑继续执行
 */
static int64_t YMHandleSysMsgRevokeMsgHook(int64_t a1, int64_t a2) {
    YMLog(@"intercepted revoke message, a1=0x%llx, a2=0x%llx",
          (unsigned long long)a1,
          (unsigned long long)a2);

    BOOL inserted = YMInsertLocalAntiRevokeNotice(a2);

    YMLog(@"insert local anti revoke notice result=%d", inserted ? 1 : 0);

    return 1;
}

#pragma mark - 安装 Patch

static BOOL YMPatchAntiRevokeWithSlide(intptr_t slide, NSString *source) {
    if (YMHasPatchedAntiRevoke) {
        YMLog(@"already installed, skip. source=%@", source);
        return YES;
    }

    const YMWeChatAdaptProfile *profile = YMGetActiveProfile();
    if (!profile) {
        YMLog(@"no active profile, skip patch");
        return NO;
    }

    YMWeChatDylibSlide = (uintptr_t)slide;

    uintptr_t pointerAddress = YMRuntimeAddress(profile->hookPointerVA);
    uintptr_t hookAddress = (uintptr_t)&YMHandleSysMsgRevokeMsgHook;

    YMLog(@"try install revoke hook from %@, profile=%s, slide=0x%lx, pointer=0x%lx, hook=0x%lx",
          source,
          profile->displayName,
          (unsigned long)YMWeChatDylibSlide,
          (unsigned long)pointerAddress,
          (unsigned long)hookAddress);

    /*
     这里不再 patch 0x27A03A0 代码段。
     而是写微信自己预留/编译出来的函数指针 off_91EAD20。

     好处：
       1. 能拿到 a1/a2 参数
       2. 可以在 hook 里自己插入提示消息
       3. 不需要改 __TEXT 指令
    */
//    BOOL ok = YMWritePointer(pointerAddress,
//                             hookAddress,
//                             0,
//                             "revoke hook pointer -> YMHandleSysMsgRevokeMsgHook");
    
    BOOL ok = NO;

    if (profile->hookMode == YMRevokeHookModePointer) {
        /*
         4.1.9：
         写微信自己预留的 off_91EAD20 函数指针。
         */
        ok = YMWritePointer(pointerAddress,
                            hookAddress,
                            0,
                            "revoke hook pointer -> YMHandleSysMsgRevokeMsgHook");
    } else if (profile->hookMode == YMRevokeHookModeInline) {
        /*
         4.1.10：
         没有 off_xxx 热补丁指针，只能直接 patch 函数入口。
         */
        ok = YMPatchARM64AbsoluteJump(pointerAddress,
                                      hookAddress,
                                      "revoke inline hook -> YMHandleSysMsgRevokeMsgHook");
    } else {
        YMLog(@"unknown revoke hook mode: %d", profile->hookMode);
        ok = NO;
    }

    if (ok) {
        YMHasPatchedAntiRevoke = YES;
    }

    return ok;
}

#pragma mark - dyld 查找 wechat.dylib

static BOOL YMIsTargetWeChatResourceDylibPath(NSString *imagePath) {
    if (imagePath.length == 0) {
        return NO;
    }

    BOOL isTarget =
    [imagePath hasSuffix:@"/Contents/Resources/wechat.dylib"] ||
    ([imagePath containsString:@"/Contents/Resources/"] &&
     [[imagePath lastPathComponent] isEqualToString:@"wechat.dylib"]);

    return isTarget;
}

static BOOL YMFindAndPatchLoadedWeChatResourceDylib(void) {
    uint32_t count = _dyld_image_count();

    YMLog(@"scan dyld images, count=%u", count);

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) {
            continue;
        }

        NSString *imagePath = [NSString stringWithUTF8String:name];

        if (!YMIsTargetWeChatResourceDylibPath(imagePath)) {
            continue;
        }

        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        YMLog(@"found loaded Resources/wechat.dylib: index=%u, slide=0x%lx, path=%@",
              i,
              (unsigned long)slide,
              imagePath);

        return YMPatchAntiRevokeWithSlide(slide, @"dyld image scan");
    }

    YMLog(@"Resources/wechat.dylib not found in dyld image list");
    return NO;
}

static void YMInstallAntiRevokePatch(void) {
    if (YMHasPatchedAntiRevoke) {
        return;
    }

    if (!YMIsTargetWeChatVersion()) {
        return;
    }

    YMFindAndPatchLoadedWeChatResourceDylib();
}

#pragma mark - 多开 Patch

static BOOL YMPatchMultiOpenWithWeChatDylibSlide(intptr_t slide, NSString *source) {
    if (YMHasPatchedMultiOpenResourceDylib) {
        YMLog(@"multi open already patched, skip. source=%@", source);
        return YES;
    }

    /*
     这里仍然复用你的版本匹配逻辑。
     避免地址漂移后误 patch 新版本。
     */
    if (!YMIsTargetWeChatVersion()) {
        YMLog(@"multi open unsupported version, skip. source=%@", source);
        return NO;
    }

    YMWeChatDylibSlide = (uintptr_t)slide;

    uintptr_t tryPreventAddress = YMRuntimeAddress(YMActiveProfile->YMMultiOpenTryPreventMultiInstanceVA);

    YMLog(@"try install multi open patch from %@, slide=0x%lx, sub_1C0A64=0x%lx",
          source,
          (unsigned long)YMWeChatDylibSlide,
          (unsigned long)tryPreventAddress);

    BOOL ok1 = YMPatchARM64ReturnYES(tryPreventAddress,
                                     "multi open: Resources/wechat.dylib::sub_1C0A64 TryPreventMultiInstance");

    YMHasPatchedMultiOpenResourceDylib = ok1;

    YMLog(@"multi open patch summary: sub_1C0A64=%@, final=%@",
          ok1 ? @"OK" : @"FAIL",
          YMHasPatchedMultiOpenResourceDylib ? @"OK" : @"FAIL");

    return YMHasPatchedMultiOpenResourceDylib;
}

static BOOL YMFindAndPatchLoadedMultiOpenWeChatDylib(void) {
    uint32_t count = _dyld_image_count();

    YMLog(@"scan dyld images for multi open, count=%u", count);

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) {
            continue;
        }

        NSString *imagePath = [NSString stringWithUTF8String:name];

        if (!YMIsTargetWeChatResourceDylibPath(imagePath)) {
            continue;
        }

        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        YMLog(@"found Resources/wechat.dylib for multi open: index=%u, slide=0x%lx, path=%@",
              i,
              (unsigned long)slide,
              imagePath);

        return YMPatchMultiOpenWithWeChatDylibSlide(slide, @"dyld image scan");
    }

    YMLog(@"Resources/wechat.dylib not found for multi open");
    return NO;
}

static void YMInstallMultiOpenPatch(void) {
    if (YMHasPatchedMultiOpenResourceDylib) {
        return;
    }

    /*
     防多开发生在启动早期，所以这里不能 dispatch_after。
     constructor 进来后立刻：
       1. 注册 dyld callback
       2. 扫描已经加载的 wechat.dylib
     */
    YMRegisterDyldCallbackIfNeeded();
    YMFindAndPatchLoadedMultiOpenWeChatDylib();
}

static void YMDyldImageAdded(const struct mach_header *mh, intptr_t vmaddr_slide) {
    const char *name = NULL;

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if (_dyld_get_image_header(i) == mh) {
            name = _dyld_get_image_name(i);
            break;
        }
    }

    if (!name) {
        return;
    }

    NSString *imagePath = [NSString stringWithUTF8String:name];

    if (!YMIsTargetWeChatResourceDylibPath(imagePath)) {
        return;
    }

    YMLog(@"dyld added target Resources/wechat.dylib: %@, callback slide=0x%lx",
          imagePath,
          (unsigned long)vmaddr_slide);

    /*
     多开必须尽早 patch。
     所以只要 wechat.dylib 被 dyld 加载，就马上 patch sub_1C0A64 / sub_4396B00。
     */
    YMPatchMultiOpenWithWeChatDylibSlide(vmaddr_slide, @"dyld add image callback");

    /*
     防撤回仍然受用户开关控制。
     */
    if ([[NSUserDefaults standardUserDefaults] boolForKey:kAntiRevoke]) {
        YMPatchAntiRevokeWithSlide(vmaddr_slide, @"dyld add image callback");
    }
}

static void YMRegisterDyldCallbackIfNeeded(void) {
    if (YMHasRegisteredDyldCallback) {
        return;
    }

    YMHasRegisteredDyldCallback = YES;

    YMLog(@"register dyld add image callback");
    _dyld_register_func_for_add_image(YMDyldImageAdded);
}

#pragma mark - 功能安装

static void YMInstallAssistantMenu(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [[MenuManager shareInstance] initAssistantMenuItems];
    });
}

static void YMInstallAntiUpdateIfNeeded(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        NSString *loadFlag = [[NSUserDefaults standardUserDefaults] objectForKey:kIsFirstLoad];
        if (loadFlag.length < 3) {
            [[NSUserDefaults standardUserDefaults] setBool:YES forKey:kAntiUpdate];
            [[NSUserDefaults standardUserDefaults] setObject:@"SOVIET" forKey:kIsFirstLoad];
        }

        if ([[NSUserDefaults standardUserDefaults] boolForKey:kAntiUpdate]) {
            YMDisableSparkleAutoUpdateDefaults();
            YMDisableSparkleByRuntimeHook();
        }
    });
}

static void YMInstallAntiRevokeIfNeeded(void) {
    if (![[NSUserDefaults standardUserDefaults] boolForKey:kAntiRevoke]) {
        YMLog(@"anti revoke disabled by user defaults, skip");
        return;
    }

    /*
     先注册 dyld 回调。
     如果 wechat.dylib 在我们之后加载，可以第一时间拿到 slide。
    */
    YMRegisterDyldCallbackIfNeeded();

    /*
     再主动扫描一次。
     如果 wechat.dylib 在我们之前已经加载，可以直接安装 hook。
    */
    YMInstallAntiRevokePatch();

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        YMInstallAntiRevokePatch();
    });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        YMInstallAntiRevokePatch();
    });
}


#pragma mark - constructor

__attribute__((constructor))
static void YMWeChatAntiRevokePatchEntry(void) {
    @autoreleasepool {
        YMLog(@"constructor called");
        /// 多开必须尽早执行，不能 dispatch_after。
        YMInstallMultiOpenPatch();

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [[MenuManager shareInstance] initAssistantMenuItems];
        });
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            NSString *loadFlag = [[NSUserDefaults standardUserDefaults] objectForKey:kIsFirstLoad];
            if (loadFlag.length < 3) {
                [[NSUserDefaults standardUserDefaults] setBool:YES forKey:kAntiUpdate];
                [[NSUserDefaults standardUserDefaults] setObject:@"SOVIET" forKey:kIsFirstLoad];
            }
            
            if ([[NSUserDefaults standardUserDefaults] boolForKey:kAntiUpdate]) {
                YMDisableSparkleAutoUpdateDefaults();
                YMDisableSparkleByRuntimeHook();
            }
        });
        
        
        if ([[NSUserDefaults standardUserDefaults] boolForKey:kAntiRevoke]) {
            /*
             先注册 dyld 回调。
             如果 wechat.dylib 在我们之后加载，可以第一时间拿到 slide。
            */
            YMRegisterDyldCallbackIfNeeded();

            /*
             再主动扫描一次。
             如果 wechat.dylib 在我们之前已经加载，可以直接安装 hook。
            */
            YMInstallAntiRevokePatch();

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                YMInstallAntiRevokePatch();
            });

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                YMInstallAntiRevokePatch();
            });
        }

    }
}

