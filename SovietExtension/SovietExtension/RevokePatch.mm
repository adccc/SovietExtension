//
//  RevokePatch.mm
//  SovietExtension
//
//  Created by MustangYM on 2026/6/12.
//
// 我燃尽了, 宝宝们, 太鸡儿麻烦了, 但我还是想说, 开源共产主义, 爱你们
//                                   -- MustangYM 2026-6-16

#import "RevokePatch.h"
#import "AntiUpdate.h"
#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <libkern/OSCacheControl.h>
#import <unistd.h>
#import <string.h>
#import <stdint.h>
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

#pragma mark - 微信 4.1.9 / 268602 arm64 静态地址

/*
 当前适配版本：
 CFBundleShortVersionString = 4.1.9
 CFBundleVersion = 268602
 Resources/wechat.dylib arm64

 注意：
 这些都是 IDA/Hopper 里的静态 VM 地址。
 运行时地址 = YMWeChatDylibSlide + 静态地址。
 */

// ym_HandleSysMsg_RevokeMsg 开头的热补丁函数指针。
// 汇编：
//   ADRP X9, #off_91EAD20@PAGE
//   LDR  X9, [X9,#off_91EAD20@PAGEOFF]
//   CBZ  X9, loc_27A03B0
//   BR   X9
static const uintptr_t kOff_HandleSysMsgRevokeMsgHookPointerVA = 0x91EAD20;

// ym_HandleSysMsg_RevokeMsg 原函数里用来构造撤回 MessageWrap 的模板：unk_7861730
static const uintptr_t kRevokeRawMessageTemplateVA = 0x7861730;

// sub_37FB284 / red_envelope_service_handler.cc 里用来构造本地系统消息的模板：unk_7969710
static const uintptr_t kLocalSysMessageTemplateVA = 0x7969710;

// MessageWrap 相关函数
static const uintptr_t kMessageWrapInitVA          = 0x245CF20;
static const uintptr_t kMessageWrapFromRawVA       = 0x4728670;
static const uintptr_t kMessageWrapSetMsgTypeVA    = 0x472800C;
static const uintptr_t kMessageWrapParseContentVA  = 0x4728618;
static const uintptr_t kMessageWrapDestructVA      = 0x206F0D0;
// 现成的本地系统消息插入函数。
// sub_3822FA4：内部会构造 type=10000 + paymsg XML，然后调用 ym_AddLocalMessageWrap。
static const uintptr_t kInsertPaySysMsgToSessionVA = 0x3822FA4;

// 从 sys_extinfo / MessageWrap 中拿 message service 的链路。
// 这组来自 paymsg / red_envelope 插入本地系统消息的反编译逻辑。
static const uintptr_t kSub413C7ACVA = 0x413C7AC;
static const uintptr_t kSub3919E18VA = 0x3919E18;
static const uintptr_t kSub2065A44VA = 0x2065A44;

// 插入本地消息到聊天流 / 消息系统
static const uintptr_t kAddLocalMessageWrapVA = 0x27AF630;

#pragma mark - 微信内部函数类型

typedef void     (*YMMessageWrapInitFunc)(void *message);
typedef void     (*YMMessageWrapFromRawFunc)(void *message, int64_t rawMessage);
typedef void     (*YMMessageWrapSetMsgTypeFunc)(void *message, uint32_t msgType);
typedef int64_t  (*YMMessageWrapParseContentFunc)(int64_t message, int flag);
typedef void     (*YMMessageWrapDestructFunc)(int64_t message);

typedef void     (*YMSub413C7ACFunc)(void *outSharedPtr, int64_t object);
typedef void     (*YMSub3919E18Func)(void *outSharedPtr, void *inSharedPtr);
typedef void     (*YMSub2065A44Func)(void *outSharedPtr, int64_t object);
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
typedef int64_t  (*YMAddLocalMessageWrapFunc)(int64_t messageService, void *message);

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

#pragma mark - 版本检查

static BOOL YMIsTargetWeChatVersion(void) {
    NSBundle *bundle = [NSBundle mainBundle];

    NSString *bundleID = [bundle bundleIdentifier] ?: @"";
    NSString *shortVersion = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    NSString *buildVersion = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";

    YMLog(@"bundleID=%@, version=%@, build=%@", bundleID, shortVersion, buildVersion);

    if (![bundleID isEqualToString:@"com.tencent.xinWeChat"]) {
        YMLog(@"not target bundle, skip");
        return NO;
    }

    if (![shortVersion isEqualToString:@"4.1.9"]) {
        YMLog(@"unsupported short version, skip");
        return NO;
    }

    if (![buildVersion isEqualToString:@"268602"]) {
        YMLog(@"unsupported build version, skip");
        return NO;
    }

    return YES;
}

#pragma mark - C++ std::string 辅助

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

/*
 第一版先默认使用纯文本系统消息。
 老版 WeChatExtension 也是类似逻辑：msgType=10000 + content 文案。
 如果纯文本不显示，再把这里改成 XML 版本测试。
 */
static std::string YMBuildAntiRevokeSystemContent(void) {
    return YMStdStringFromNSString(@"已拦截到一条撤回消息");
}

/*
 备用 XML 版本。
 如果纯文本版本插入了但 UI 不显示，可以把 YMBuildAntiRevokeSystemContent()
 里 return 改成这个函数。
 */
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
    if (YMWeChatDylibSlide == 0) {
        YMLog(@"insert local notice failed: YMWeChatDylibSlide is zero");
        return NO;
    }

    if (rawRevokeMessage == 0) {
        YMLog(@"insert local notice failed: rawRevokeMessage is zero");
        return NO;
    }

    YMLog(@"try insert local anti revoke notice by sub_3822FA4, rawRevokeMessage=0x%llx",
          (unsigned long long)rawRevokeMessage);

    YMMessageWrapFromRawFunc MessageWrapFromRaw =
    (YMMessageWrapFromRawFunc)(YMWeChatDylibSlide + kMessageWrapFromRawVA);

    YMMessageWrapDestructFunc MessageWrapDestruct =
    (YMMessageWrapDestructFunc)(YMWeChatDylibSlide + kMessageWrapDestructVA);

    YMInsertPaySysMsgToSessionFunc InsertPaySysMsgToSession =
    (YMInsertPaySysMsgToSessionFunc)(YMWeChatDylibSlide + kInsertPaySysMsgToSessionVA);

    /*
     rawWrap：
     复刻 ym_HandleSysMsg_RevokeMsg 原始逻辑：

       memcpy(rawWrap, unk_7861730, 616)
       sub_4728670(rawWrap, rawRevokeMessage)

     目的：
       只为了从 rawWrap 里拿到会话字段。
    */
    alignas(16) uint8_t rawWrap[616];
    memset(rawWrap, 0, sizeof(rawWrap));

    void *rawTemplate = (void *)(YMWeChatDylibSlide + kRevokeRawMessageTemplateVA);
    memcpy(rawWrap, rawTemplate, sizeof(rawWrap));

    MessageWrapFromRaw(rawWrap, rawRevokeMessage);

    BOOL ok = NO;

    try {
        std::string *rawField24 = (std::string *)(rawWrap + 24);
        std::string *rawField48 = (std::string *)(rawWrap + 48);

        YMLog(@"raw field24=%s", rawField24->c_str());
        YMLog(@"raw field48=%s", rawField48->c_str());

        /*
         从实际测试结果看：
           rawField24 = 对方 / 当前聊天会话
           rawField48 = 当前登录账号 / 自己

         所以这里必须用 rawField24 作为 session。
         */
        std::string *remoteUserOrSession = rawField24;
        std::string *selfUser = rawField48;

        std::string *session = remoteUserOrSession;

        if (session->empty()) {
            YMLog(@"rawField24 is empty, fallback to rawField48");
            session = rawField48;
        }

        if (session->empty()) {
            YMLog(@"insert local notice failed: session is empty");
            MessageWrapDestruct((int64_t)rawWrap);
            return NO;
        }

        uint32_t rawCreateTimeSec = *(uint32_t *)(rawWrap + 276);
        uint64_t rawCreateTimeMs  = *(uint64_t *)(rawWrap + 256);

        NSTimeInterval messageTimestamp = 0;

        if (rawCreateTimeSec > 0) {
            messageTimestamp = (NSTimeInterval)rawCreateTimeSec;
        } else if (rawCreateTimeMs > 0) {
            messageTimestamp = (NSTimeInterval)(rawCreateTimeMs / 1000);
        } else {
            messageTimestamp = [[NSDate date] timeIntervalSince1970];
        }

        NSDate *messageDate = [NSDate dateWithTimeIntervalSince1970:messageTimestamp];

        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        formatter.locale = [NSLocale localeWithLocaleIdentifier:@"zh_CN"];
        formatter.timeZone = [NSTimeZone localTimeZone];
        formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";

        NSString *messageTimeText = [formatter stringFromDate:messageDate];

        NSString *noticeText = [NSString stringWithFormat:
                                @"⚠️苏维埃已拦截到一条撤回消息⚠️\n撤回方/会话：%s\n消息时间：%@\nraw：0x%llx",
                                remoteUserOrSession->c_str(),
                                messageTimeText,
                                (unsigned long long)rawRevokeMessage];

        std::string content = YMStdStringFromNSString(noticeText);

        YMLog(@"insert notice session=%s", session->c_str());
        YMLog(@"insert notice remoteUserOrSession=%s", remoteUserOrSession->c_str());
        YMLog(@"insert notice selfUser=%s", selfUser->c_str());
        YMLog(@"insert notice content=%s", content.c_str());
        YMLog(@"call sub_3822FA4 at 0x%lx",
              (unsigned long)(YMWeChatDylibSlide + kInsertPaySysMsgToSessionVA));

        int64_t result = InsertPaySysMsgToSession(0, session, &content);

        YMLog(@"sub_3822FA4 result=0x%llx", (unsigned long long)result);

        ok = YES;
    } catch (...) {
        YMLog(@"exception while calling sub_3822FA4 insert local notice");
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

    if (!YMIsTargetWeChatVersion()) {
        return NO;
    }

    YMWeChatDylibSlide = (uintptr_t)slide;

    uintptr_t pointerAddress = YMWeChatDylibSlide + kOff_HandleSysMsgRevokeMsgHookPointerVA;
    uintptr_t hookAddress = (uintptr_t)&YMHandleSysMsgRevokeMsgHook;

    YMLog(@"try install revoke hook from %@, slide=0x%lx, pointer=0x%lx, hook=0x%lx",
          source,
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
    BOOL ok = YMWritePointer(pointerAddress,
                             hookAddress,
                             0,
                             "off_91EAD20 -> YMHandleSysMsgRevokeMsgHook");

    if (ok) {
        YMHasPatchedAntiRevoke = YES;
    }

    return ok;
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

        BOOL isTarget =
        [imagePath hasSuffix:@"/Contents/Resources/wechat.dylib"] ||
        ([imagePath containsString:@"/Contents/Resources/"] &&
         [[imagePath lastPathComponent] isEqualToString:@"wechat.dylib"]);

        if (!isTarget) {
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

    BOOL isTarget =
    [imagePath hasSuffix:@"/Contents/Resources/wechat.dylib"] ||
    ([imagePath containsString:@"/Contents/Resources/"] &&
     [[imagePath lastPathComponent] isEqualToString:@"wechat.dylib"]);

    if (!isTarget) {
        return;
    }

    YMLog(@"dyld added target image: %@, callback slide=0x%lx",
          imagePath,
          (unsigned long)vmaddr_slide);

    YMPatchAntiRevokeWithSlide(vmaddr_slide, @"dyld add image callback");
}

#pragma mark - constructor

__attribute__((constructor))
static void YMWeChatAntiRevokePatchEntry(void) {
    @autoreleasepool {
        YMLog(@"constructor called");

        ///TODO 多开
//        [NSObject startHook];

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
            _dyld_register_func_for_add_image(YMDyldImageAdded);

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
