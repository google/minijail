#if defined(__i386__) || defined(__x86_64__)
#include <asm/prctl.h>
#endif // __i386__ || __x86_64__
#include <errno.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <linux/serial.h>
#include <linux/termios.h>
#include <stddef.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/types.h>
