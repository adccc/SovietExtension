//
//  MenuManager.m
//  SovietExtension
//
//  Created by MustangYM on 2026/6/13.
//

#import "MenuManager.h"
#import "NSMenuItem+Action.h"
#import "NSMenu+Action.h"
#import "YMSwizzledHelper.h"

@implementation MenuManager
+ (instancetype)shareInstance {
    static id share = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        share = [[self alloc] init];
    });
    return share;
}

- (void)initAssistantMenuItems
{
    BOOL flag_update = [[NSUserDefaults standardUserDefaults] boolForKey:kAntiUpdate];
    NSMenuItem *antiUpdateMenu = [NSMenuItem menuItemWithTitle:@"阻止更新"
                                                       action:@selector(onAntiUpdate:)
                                                       target:self
                                                keyEquivalent:@""
                                                        state:flag_update];
    
    BOOL flag_revoke = [[NSUserDefaults standardUserDefaults] boolForKey:kAntiRevoke];
    NSMenuItem *antiRevokeMenu= [NSMenuItem menuItemWithTitle:@"消息防撤回"
                                                       action:@selector(onAntiRevoke:)
                                                       target:self
                                                keyEquivalent:@""
                                                        state:flag_revoke];
    
   
    NSString *version = [NSString stringWithFormat:@"当前版本 %@", kCurrentVersion];
    NSMenuItem *currentVersionMenu= [NSMenuItem menuItemWithTitle:version
                                                       action:@selector(onAntiRevoke:)
                                                       target:self
                                                keyEquivalent:@""
                                                        state:NO];
    
    NSMenu *subMenu = [[NSMenu alloc] initWithTitle:@"苏维埃助手"];
    [subMenu addItems:@[antiUpdateMenu,
                        antiRevokeMenu,
                        currentVersionMenu
                      ]];
    
    NSMenuItem *menuItem = [[NSMenuItem alloc] init];
    menuItem.target = self;
    menuItem.enabled = YES;
    [menuItem setTitle:@"苏维埃助手"];
    [menuItem setSubmenu:subMenu];
    [[[NSApplication sharedApplication] mainMenu] addItem:menuItem];
    
}

- (void)onAntiUpdate:(NSMenuItem *)item
{
    BOOL enabled = item.state != NSControlStateValueOn;
    
    NSAlert *alert = [NSAlert alertWithMessageText:@"警告"
                                     defaultButton:@"取消"                      
                                   alternateButton:@"确定重启"
                                       otherButton:nil
                         informativeTextWithFormat:@"非必要情况千万不要关闭`禁止更新`,否则微信自动更新导致插件失效"];
    NSUInteger action = [alert runModal];
    if (action == NSAlertAlternateReturn) {
        item.state = enabled ? NSControlStateValueOn : NSControlStateValueOff;
        [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:kAntiUpdate];
        [[NSUserDefaults standardUserDefaults] synchronize];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self restartWeChat];
        });
    }  else if (action == NSAlertDefaultReturn) {
        
    }
}

- (void)onAntiRevoke:(NSMenuItem *)item
{
    BOOL enabled = item.state != NSControlStateValueOn;
    
    NSAlert *alert = [NSAlert alertWithMessageText:@"警告"
                                     defaultButton:@"取消"
                                   alternateButton:@"确定重启"
                                       otherButton:nil
                         informativeTextWithFormat:@"重启微信生效"];
    NSUInteger action = [alert runModal];
    if (action == NSAlertAlternateReturn) {
        item.state = enabled ? NSControlStateValueOn : NSControlStateValueOff;
        [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:kAntiRevoke];
        [[NSUserDefaults standardUserDefaults] synchronize];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self restartWeChat];
        });
    }  else if (action == NSAlertDefaultReturn) {
        
    }
}

- (void)onNewWeChat:(NSMenuItem *)item
{
    [self executeShellCommand:@"open -n /Applications/WeChat.app"];
}

- (void)restartWeChat
{
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *cmd = @"killall WeChat && open /Applications/WeChat.app";
        [self executeShellCommand:cmd];
    });
}

- (NSString *)executeShellCommand:(NSString *)cmd
{
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/bin/bash"];
    [task setArguments:@[@"-c", cmd]];
    // 新建输出管道作为Task的错误输出
    NSPipe *errorPipe = [NSPipe pipe];
    [task setStandardError:errorPipe];
    NSFileHandle *file = [errorPipe fileHandleForReading];
    // 获取运行结果
    [task launch];
    NSData *data = [file readDataToEndOfFile];
    
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}
@end
