#ifndef _WUWA_CTRL_H_
#define _WUWA_CTRL_H_

#include <linux/types.h>
#include <linux/ioctl.h>

struct patch_req {
    __u32 action;       // 动作类型 (0~6)
    __u32 pid;          // 目标 PID
    __u64 va;           // 触发 Hook 的精准虚拟地址 (PC)
    __u64 target_va;    // Action 2 使用的跳转目标
    __u32 patch_val;    // Action 0/4/6 的机器码或浮点数据
    __u32 patch_val_2;  // Action 4 的第二条机器码
    __u32 enabled;      // 1 开启, 0 关闭
};

#define WUWA_MAGIC 'W'
#define WUWA_IOCTL_SET_HOOK _IOW(WUWA_MAGIC, 1, struct patch_req)

#endif // _WUWA_CTRL_H_
