#ifndef _WUWA_CTRL_H_
#define _WUWA_CTRL_H_

#include <linux/types.h>
#include <linux/ioctl.h>

struct patch_req {
    __u32 action;       // 功能 ID (1:去黑边, 2:跳过, 3:无敌, 4:双修, 5:锁血, 6:全屏)
    __u32 pid;          // 目标进程 PID
    __u64 va;           // 目标虚拟地址 (精确到指令)
    __u64 target_va;    // Action 2 专用的跳转目标
    __u32 patch_val;    // 附加数据 1 (机器码或浮点)
    __u32 patch_val_2;  // 附加数据 2 (Action 4)
    __u32 enabled;      // 1 开启，0 关闭
};

#define WUWA_MAGIC 'W'
#define WUWA_IOCTL_SET_HOOK _IOW(WUWA_MAGIC, 1, struct patch_req)

#endif // _WUWA_CTRL_H_
