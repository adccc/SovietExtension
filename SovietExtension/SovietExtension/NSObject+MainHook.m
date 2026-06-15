//
//  NSObject+MainHook.m
//  SovietExtension
//
//  Created by MustangYM on 2026/6/13.
//

#import "NSObject+MainHook.h"
#import "YMSwizzledHelper.h"
#import <Foundation/Foundation.h>
#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>

#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <libkern/OSCacheControl.h>
#import <unistd.h>


static void YMLog(const char *fmt, ...)
{
    int fd = open("/tmp/ym_multiopen_patch.log",
                  O_CREAT | O_WRONLY | O_APPEND,
                  0644);
    if (fd < 0) {
        return;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);

    dprintf(fd, "[pid=%d ppid=%d time=%ld.%06d] ",
            getpid(),
            getppid(),
            tv.tv_sec,
            tv.tv_usec);

    va_list ap;
    va_start(ap, fmt);
    vdprintf(fd, fmt, ap);
    va_end(ap);

    dprintf(fd, "\n");
    close(fd);
}

#pragma mark - Image

static void YMDumpImages(void)
{
    uint32_t count = _dyld_image_count();

    YMLog("===== dyld images count = %u =====", count);

    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const char *name = _dyld_get_image_name(i);

        YMLog("image[%u] header=%p slide=0x%llx name=%s",
              i,
              header,
              (unsigned long long)slide,
              name ? name : "");
    }

    YMLog("===== dyld images end =====");
}

static uint32_t YMFindImageIndexContains(const char *keyword)
{
    uint32_t count = _dyld_image_count();

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) {
            continue;
        }

        if (strstr(name, keyword)) {
            return i;
        }
    }

    return UINT32_MAX;
}

static void *YMRuntimeAddressForImageOffset(const char *imageKeyword,
                                            uint64_t offset)
{
    uint32_t imageIndex = YMFindImageIndexContains(imageKeyword);

    if (imageIndex == UINT32_MAX) {
        YMLog("find image failed, keyword=%s", imageKeyword);
        return NULL;
    }

    const struct mach_header *header = _dyld_get_image_header(imageIndex);
    intptr_t slide = _dyld_get_image_vmaddr_slide(imageIndex);
    const char *name = _dyld_get_image_name(imageIndex);

    YMLog("use image[%u], keyword=%s, header=%p, slide=0x%llx, name=%s",
          imageIndex,
          imageKeyword,
          header,
          (unsigned long long)slide,
          name ? name : "");

    if (!header) {
        return NULL;
    }

    return (void *)((uintptr_t)header + offset);
}

#pragma mark - Patch

static BOOL YMProtectWrite(void *addr, size_t size)
{
    long pageSize = sysconf(_SC_PAGESIZE);
    uintptr_t address = (uintptr_t)addr;
    uintptr_t pageStart = address & ~((uintptr_t)pageSize - 1);
    uintptr_t pageEnd = (address + size + pageSize - 1) & ~((uintptr_t)pageSize - 1);
    size_t protectSize = pageEnd - pageStart;

    kern_return_t kr = mach_vm_protect(mach_task_self(),
                                       (mach_vm_address_t)pageStart,
                                       (mach_vm_size_t)protectSize,
                                       false,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

    if (kr != KERN_SUCCESS) {
        YMLog("mach_vm_protect RW failed, addr=%p, kr=%d", addr, kr);
        return NO;
    }

    return YES;
}

static BOOL YMProtectExecute(void *addr, size_t size)
{
    long pageSize = sysconf(_SC_PAGESIZE);
    uintptr_t address = (uintptr_t)addr;
    uintptr_t pageStart = address & ~((uintptr_t)pageSize - 1);
    uintptr_t pageEnd = (address + size + pageSize - 1) & ~((uintptr_t)pageSize - 1);
    size_t protectSize = pageEnd - pageStart;

    kern_return_t kr = mach_vm_protect(mach_task_self(),
                                       (mach_vm_address_t)pageStart,
                                       (mach_vm_size_t)protectSize,
                                       false,
                                       VM_PROT_READ | VM_PROT_EXECUTE);

    if (kr != KERN_SUCCESS) {
        YMLog("mach_vm_protect RX failed, addr=%p, kr=%d", addr, kr);
        return NO;
    }

    return YES;
}

static void YMPrintBytes(const char *name, const char *stage, void *addr)
{
    if (!addr) {
        YMLog("%s %s addr is NULL", name, stage);
        return;
    }

    uint32_t bytes[4] = {0};
    memcpy(bytes, addr, sizeof(bytes));

    YMLog("%s %s addr=%p bytes=%08x %08x %08x %08x",
          name,
          stage,
          addr,
          bytes[0],
          bytes[1],
          bytes[2],
          bytes[3]);
}

static BOOL YMPatchReturnUInt64(void *addr,
                                uint64_t value,
                                const char *name)
{
    if (!addr) {
        YMLog("%s patch failed: addr NULL", name);
        return NO;
    }

    if (value > 0xFFFF) {
        YMLog("%s patch failed: value too large %llu",
              name,
              (unsigned long long)value);
        return NO;
    }

    YMPrintBytes(name, "before", addr);

    /*
     ARM64:
     mov x0, #value
     ret

     return 1:
     0xD2800020
     0xD65F03C0

     return 0:
     0xD2800000
     0xD65F03C0
     */
    uint32_t mov_x0_imm = 0xD2800000 | ((uint32_t)value << 5);
    uint32_t ret = 0xD65F03C0;

    uint32_t patch[2] = {
        mov_x0_imm,
        ret
    };

    if (!YMProtectWrite(addr, sizeof(patch))) {
        YMLog("%s protect write failed", name);
        return NO;
    }

    memcpy(addr, patch, sizeof(patch));
    sys_icache_invalidate(addr, sizeof(patch));

    if (!YMProtectExecute(addr, sizeof(patch))) {
        YMLog("%s protect execute failed", name);
        return NO;
    }

    YMPrintBytes(name, "after", addr);

    uint32_t check[2] = {0};
    memcpy(check, addr, sizeof(check));

    BOOL ok = check[0] == mov_x0_imm && check[1] == ret;

    YMLog("%s patch return %llu result=%s",
          name,
          (unsigned long long)value,
          ok ? "OK" : "FAIL");

    return ok;
}

static BOOL YMPatchReturnVoid(void *addr,
                              const char *name)
{
    if (!addr) {
        YMLog("%s patch failed: addr NULL", name);
        return NO;
    }

    YMPrintBytes(name, "before", addr);

    uint32_t ret = 0xD65F03C0;

    if (!YMProtectWrite(addr, sizeof(ret))) {
        YMLog("%s protect write failed", name);
        return NO;
    }

    memcpy(addr, &ret, sizeof(ret));
    sys_icache_invalidate(addr, sizeof(ret));

    if (!YMProtectExecute(addr, sizeof(ret))) {
        YMLog("%s protect execute failed", name);
        return NO;
    }

    YMPrintBytes(name, "after", addr);

    uint32_t check = 0;
    memcpy(&check, addr, sizeof(check));

    BOOL ok = check == ret;

    YMLog("%s patch return void result=%s",
          name,
          ok ? "OK" : "FAIL");

    return ok;
}

#pragma mark - Install

static void YMInstallMultiOpenPatch(void)
{
    static int installed = 0;
    if (installed) {
        YMLog("YMInstallMultiOpenPatch already installed");
        return;
    }
    installed = 1;

    YMLog("========== YMInstallMultiOpenPatch begin ==========");
    YMLog("process pid=%d ppid=%d", getpid(), getppid());

    YMDumpImages();

    /*
     1. 主可执行文件：
        Contents/MacOS/WeChat

        IDA 地址：
        sub_10001fbb4

        因为主程序常见基址是 0x100000000，
        所以 offset = 0x10001fbb4 - 0x100000000 = 0x1fbb4
     */
    void *addr_main_sub_10001fbb4 =
        YMRuntimeAddressForImageOffset("/Contents/MacOS/WeChat", 0x1fbb4);

    /*
     2. 主体 dylib：
        Contents/Resources/WeChat.dylib

        你之前贴的：
        sub_1C0A64
        sub_4396B00
     */
    void *addr_dylib_sub_1C0A64 =
        YMRuntimeAddressForImageOffset("/Contents/Resources/wechat.dylib", 0x1C0A64);

    void *addr_dylib_sub_4396B00 =
        YMRuntimeAddressForImageOffset("/Contents/Resources/wechat.dylib", 0x4396B00);

    YMLog("addr main sub_10001fbb4 = %p", addr_main_sub_10001fbb4);
    YMLog("addr dylib sub_1C0A64 = %p", addr_dylib_sub_1C0A64);
    YMLog("addr dylib sub_4396B00 = %p", addr_dylib_sub_4396B00);

    /*
     sub_10001fbb4:
     先试 return 1。

     如果它的语义是：
     “旧 pid 是否 terminated？”
     return 1 就是告诉上层：旧实例已结束。
     */
    BOOL ok0 = YMPatchReturnUInt64(addr_main_sub_10001fbb4,
                                   1,
                                   "main::sub_10001fbb4");

    /*
     dylib 里的两个：
     TryPreventMultiInstance -> return 1
     GetMainWeixinProcessCount -> return 1
     */
    BOOL ok1 = YMPatchReturnUInt64(addr_dylib_sub_1C0A64,
                                   1,
                                   "dylib::sub_1C0A64");

    BOOL ok2 = YMPatchReturnUInt64(addr_dylib_sub_4396B00,
                                   1,
                                   "dylib::sub_4396B00");

    YMLog("patch summary: main_sub_10001fbb4=%s dylib_sub_1C0A64=%s dylib_sub_4396B00=%s",
          ok0 ? "OK" : "FAIL",
          ok1 ? "OK" : "FAIL",
          ok2 ? "OK" : "FAIL");

    YMLog("========== YMInstallMultiOpenPatch end ==========");
}

__attribute__((constructor))
static void YMMultiOpenPatchConstructor(void)
{
    YMLog("YMMultiOpenPatchConstructor called");
    YMInstallMultiOpenPatch();
}

@implementation NSObject (MainHook)


+ (void)startHook
{
 
    hookClassMethod(objc_getClass("NSRunningApplication"),
                       @selector(runningApplicationsWithBundleIdentifier:),
                       [self class],
                       @selector(hook_runningApplicationsWithBundleIdentifier:));
    
}

+ (NSArray *)hook_runningApplicationsWithBundleIdentifier:(NSString *)bundleIdentifier
{
    NSString *mainBundleID = [[NSBundle mainBundle] bundleIdentifier];

    NSLog(@"[MultiOpen] query bundleIdentifier = %@, mainBundleID = %@, pid = %d",
          bundleIdentifier,
          mainBundleID,
          getpid());

    if (bundleIdentifier.length > 0 &&
        mainBundleID.length > 0 &&
        [bundleIdentifier isEqualToString:mainBundleID]) {
        
        NSRunningApplication *currentApp = [NSRunningApplication currentApplication];
        
        NSLog(@"[MultiOpen] fake running apps count = 1, current pid = %d", getpid());
        
        return currentApp ? @[currentApp] : @[];
    }

    return [self hook_runningApplicationsWithBundleIdentifier:bundleIdentifier];
}
@end
