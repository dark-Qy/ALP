#ifndef __DEBUG_H__

#define __DEBUG_H__

#define IN      // 标记输入参数
#define OUT     // 标记输出参数
#define INOUT   // 标记输入输出参数

#define DEBUG_ENABLE 1
#if DEBUG_ENABLE

#ifdef __KERNEL__
#define DEBUG_PRINT(fmt, args...) printk(fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...) printf(fmt, ##args)
#endif

#else
#define DEBUG_PRINT(fmt, args...)
#endif

#endif