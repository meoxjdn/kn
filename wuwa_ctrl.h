#ifndef _WUWA_CTRL_H_
#define _WUWA_CTRL_H_

#include <linux/types.h>
#include <linux/ioctl.h>

struct patch_req {
    __u32 action;       // 动作类型 (1:RET, 2:B, 3:GodMode, 5:SafeHP, 6:FloatRet)
    __u32 pid;          // 目标 PID
    __u64 va;           // 触发 Hook 的精准虚拟地址 (PC)
    __u64 target_va;    // Action 2 使用的跳转目标
    __u32 patch_val;    // Action 6 等使用的浮点机器码或附加数据
    __u32 enabled;      // 1 开启, 0 关闭
};

#define WUWA_MAGIC 'W'
#define WUWA_IOCTL_SET_HOOK _IOW(WUWA_MAGIC, 1, struct patch_req)

#endif // _WUWA_CTRL_H_
