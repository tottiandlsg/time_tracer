#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/sizes.h>
#include <linux/stacktrace.h>
#include <linux/timer.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <trace/events/sched.h>
#include <linux/string.h>
#include <linux/sched/clock.h>
#include <linux/sched/task.h>
#include <linux/sched/stat.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/tracepoint.h>
#include <asm/irq_regs.h>


#define NUM_TRACEPOINTS			      1
#define MAX_TRACE_ENTRIES		      2000   //栈缓存最大支持2000条记录
#define MAX_STACE_TRACE_ENTRIES       200    //线程超时记录最大支持200条   	      

struct tracepoint_entry 
{
	void *probe;
	const char *name;
	struct tracepoint *tp;
};

//用于记录栈，nr_entries代表记录当前函数栈的条数，entries代表当前函数栈的首地址
struct stack_entry 
{
	unsigned int nr_entries;
	unsigned long *entries;
};

struct per_cpu_stack_trace 
{
	u64 last_timestamp;
	struct hrtimer hrtimer;
	struct task_struct *skip;

	unsigned int nr_stack_entries;
	unsigned int nr_entries;
	struct stack_entry stack_entries[MAX_STACE_TRACE_ENTRIES];   
	unsigned long entries[MAX_TRACE_ENTRIES];             //函数栈指针的实际存放

	char comms[MAX_STACE_TRACE_ENTRIES][TASK_COMM_LEN];   //记录超时线程的名字
	pid_t pids[MAX_STACE_TRACE_ENTRIES];                  //记录超时线程的pid
	u64 duration[MAX_STACE_TRACE_ENTRIES];                //记录超时线程的连续运行时间
};


struct noschedule_info
{
	struct tracepoint_entry tp_entries[NUM_TRACEPOINTS];
	unsigned int tp_initalized;

	struct per_cpu_stack_trace __percpu *stack_trace;
};
	

struct dentry *time_tracer = NULL;

static size_t trace_enable = 0;

static u64 sampling_period = 10 * 1000 * 1000UL;  //10ms htimer检测周期

static u64 duration_threshold = 50 * 1000 * 1000UL;  //50ms 线程独占CPU触发事件



static void probe_sched_switch(void *priv, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	u64 now = local_clock();
	struct per_cpu_stack_trace __percpu *stack_trace = priv;
	struct per_cpu_stack_trace *cpu_stack_trace = this_cpu_ptr(stack_trace);
	u64 last = cpu_stack_trace->last_timestamp;

	if (unlikely(!trace_enable))
		return;

	cpu_stack_trace->last_timestamp = now;
	if (unlikely(cpu_stack_trace->skip)) {
		unsigned int index = cpu_stack_trace->nr_stack_entries - 1;

		cpu_stack_trace->skip = NULL;
		cpu_stack_trace->duration[index] = now - last;
	}

}



static struct noschedule_info nosched_info = {
	.tp_entries = {
		[0] = {
			.name	= "sched_switch",
			.probe	= probe_sched_switch,
		},
	},
	.tp_initalized = 0,
};


static int trace_nosched_register_tp(void)
{
	int i;
	struct noschedule_info *info = &nosched_info;

	for (i = 0; i < ARRAY_SIZE(info->tp_entries); i++) 
    {
		int ret;
		struct tracepoint_entry *entry = info->tp_entries + i;
		ret = tracepoint_probe_register(entry->tp, entry->probe, info->stack_trace);
		if (ret && ret != -EEXIST) 
        {
			pr_err("sched trace: can not activate tracepoint probe to %s with error code: %d\n", entry->name, ret);
			while (i--) 
            {
				entry = info->tp_entries + i;
				tracepoint_probe_unregister(entry->tp, entry->probe, info->stack_trace);
			}
			return ret;
		}
	}

	return 0;
}

static int trace_nosched_unregister_tp(void)
{
	int i;
	struct noschedule_info *info = &nosched_info;

	for (i = 0; i < ARRAY_SIZE(info->tp_entries); i++) 
    {
		int ret;
		ret = tracepoint_probe_unregister(info->tp_entries[i].tp, info->tp_entries[i].probe, info->stack_trace);
		if (ret && ret != -ENOENT) 
        {
			pr_err("sched trace: can not inactivate tracepoint probe to %s with error code: %d\n", info->tp_entries[i].name, ret);
			return ret;
		}
	}
    
	return 0;
}

static inline bool is_tracepoint_lookup_success(struct noschedule_info *info)
{
	return info->tp_initalized == ARRAY_SIZE(info->tp_entries);
}


static void __init tracepoint_lookup(struct tracepoint *tp, void *priv)
{
	int i;
	struct noschedule_info *info = priv;

	if (is_tracepoint_lookup_success(info))
		return;

	for (i = 0; i < ARRAY_SIZE(info->tp_entries); i++) {
		if (info->tp_entries[i].tp || !info->tp_entries[i].name ||
		    strcmp(tp->name, info->tp_entries[i].name))
			continue;
		info->tp_entries[i].tp = tp;
		info->tp_initalized++;
	}
}



static inline void store_stack_trace(struct pt_regs *regs,
				     struct stack_entry *stack_entry,
				     unsigned long *entries,
				     unsigned int max_entries, int skip)
{
	struct stack_trace stack_trace;

	stack_trace.nr_entries = 0;
	stack_trace.max_entries = max_entries;
	stack_trace.entries = entries;
	stack_trace.skip = skip;
    save_stack_trace(&stack_trace);
	stack_entry->entries = entries;
	stack_entry->nr_entries = stack_trace.nr_entries;

	if (stack_entry->nr_entries != 0 && stack_entry->entries[stack_entry->nr_entries - 1] == ULONG_MAX)
		stack_entry->nr_entries--;
}



static bool __stack_trace_record(struct per_cpu_stack_trace *stack_trace,
				 struct pt_regs *regs, u64 duration)
{
	unsigned int nr_entries, nr_stack_entries;
	struct stack_entry *stack_entry;

	nr_stack_entries = stack_trace->nr_stack_entries;
	if (nr_stack_entries >= ARRAY_SIZE(stack_trace->stack_entries))
		return false;

	nr_entries = stack_trace->nr_entries;
	if (nr_entries >= ARRAY_SIZE(stack_trace->entries))
		return false;

	strlcpy(stack_trace->comms[nr_stack_entries], current->comm, TASK_COMM_LEN);
	stack_trace->pids[nr_stack_entries] = current->pid;
	stack_trace->duration[nr_stack_entries] = duration;

	stack_entry = stack_trace->stack_entries + nr_stack_entries;
	store_stack_trace(regs, stack_entry, stack_trace->entries + nr_entries,
			  ARRAY_SIZE(stack_trace->entries) - nr_entries, 0);
	stack_trace->nr_entries += stack_entry->nr_entries;
    
	smp_store_release(&stack_trace->nr_stack_entries, nr_stack_entries + 1);

	if (unlikely(stack_trace->nr_entries >=
		     ARRAY_SIZE(stack_trace->entries))) {
		pr_info("BUG: MAX_TRACE_ENTRIES too low on cpu: %d!\n",
			smp_processor_id());

		return false;
	}

	return true;
}

/* Note: Must be called with irq disabled. */
static inline bool stack_trace_record(struct per_cpu_stack_trace *stack_trace,
				      u64 delta)
{
	if (unlikely(delta >= duration_threshold))
		return __stack_trace_record(stack_trace, get_irq_regs(), delta);

	return false;
}



static enum hrtimer_restart trace_nosched_hrtimer_handler(struct hrtimer *hrtimer)
{
	struct per_cpu_stack_trace *stack_trace;
	u64 now = local_clock();
	stack_trace = container_of(hrtimer, struct per_cpu_stack_trace, hrtimer);
    //idle进程或者当前核心只有一个任务的不进行计算
	if (!is_idle_task(current) && !single_task_running()) 
    {
		u64 delta;

		delta = now - stack_trace->last_timestamp;
		if (!stack_trace->skip && stack_trace_record(stack_trace, delta))
        { 
			stack_trace->skip = current;
        }
	} 
    else 
    {
		stack_trace->last_timestamp = now;
	}

	hrtimer_forward_now(hrtimer, ns_to_ktime(sampling_period));

	return HRTIMER_RESTART;
}

static void each_hrtimer_start(void *priv)
{
    u64 now = local_clock();
    struct per_cpu_stack_trace __percpu *stack_trace = priv;
    struct hrtimer *hrtimer = this_cpu_ptr(&stack_trace->hrtimer);

    hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_PINNED);
	hrtimer->function = trace_nosched_hrtimer_handler;

    __this_cpu_write(stack_trace->last_timestamp, now);

    hrtimer_start_range_ns(hrtimer, ns_to_ktime(sampling_period), 0, HRTIMER_MODE_REL_PINNED);
}

static inline void trace_nosched_hrtimer_start(void)
{
    //on_each_cpu的作用是在每个核心上执行一次当前的函数，整个操作流程是通过调用smp_call_function函数，让smp的其他核心先执行这个函数
    //smp_call_function实现实际上是通过内核间中断ipi来实现的，即当前CPU向其他CPU发送内核间中断的消息，其他的内核进入中断，在中断中执行当前函数
    //在调用完smp_call_function函数之后，在单独执行这个函数，来完成当前核心的处理
	on_each_cpu(each_hrtimer_start, nosched_info.stack_trace, true);
}

static inline void trace_nosched_hrtimer_cancel(void)
{
	int cpu;

	for_each_online_cpu(cpu)
		hrtimer_cancel(per_cpu_ptr(&nosched_info.stack_trace->hrtimer, cpu));
}

static int enable_show(struct seq_file *m, void *ptr)
{
    seq_printf(m, "%s\n", trace_enable ? "enabled" : "disabled");
    return 0;
}

static ssize_t enable_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    long enable;
    ssize_t retval = 0;
    retval = kstrtol(buf, 0, &enable);
    if(retval)
    {
        printk("kstrtol translate buf err\n");
        return retval;
    }
    if(!!enable == !! trace_enable)
    {
        return count;
    }

    if(enable)
    {
        if(!trace_nosched_register_tp())
	        trace_nosched_hrtimer_start();
        else
        {
            printk("timer trace can not enable\n");
            return -EAGAIN;
        }
    }
    else
    {
        trace_nosched_hrtimer_cancel();
        if(trace_nosched_unregister_tp())
        {
            printk("timer trace can not disable\n");
            return -EAGAIN;
        }
    }
    
    trace_enable = (size_t)enable;
    
    return count;
}


static int enable_open(struct inode *inode, struct file *file)
{
	return single_open(file, enable_show, inode->i_private);
}

static const struct file_operations enable_fops = {
	.open		= enable_open,
	.read		= seq_read,
	.write      = enable_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int duration_show(struct seq_file *m, void *ptr)
{
    unsigned int i;
    int cpu;
    struct per_cpu_stack_trace *time_trace;
    for_each_online_cpu(cpu)
    {
        time_trace = per_cpu_ptr(nosched_info.stack_trace,cpu);
        for(i = 0; i < MAX_STACE_TRACE_ENTRIES; i++)
        {
            if(time_trace->duration[i] != 0)
            {
                seq_printf(m, "time trace the out of limit procee pid is %d, the duration is %lld, the cpu is %d\n\n", 
                    time_trace->pids[i], time_trace->duration[i]/1000, cpu);
            }
        }
    }
    return 0;
}

static int duration_open(struct inode *inode, struct file *file)
{
	return single_open(file, duration_show, inode->i_private);
}

static const struct file_operations duration_fops = {
	.open		= duration_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int stack_show(struct seq_file *m, void *ptr)
{
    unsigned int i, j;
    int cpu;
    struct per_cpu_stack_trace *time_trace;
    struct stack_entry *entry;
    for_each_online_cpu(cpu)
    {
        seq_printf(m, "\n--------------------------\n");
        seq_printf(m, "this is cpu%d stack\n", cpu);
        time_trace = per_cpu_ptr(nosched_info.stack_trace,cpu);
        for(i = 0; i < time_trace->nr_stack_entries; i++)
        {
            entry = time_trace->stack_entries + i;
            for(j = 0; j < entry->nr_entries; j++)
            {
                seq_printf(m, "%*c%pS\n", 1, ' ', (void *)entry->entries[j]);
            }
            seq_printf(m, "--------------------------\n");
        }
    }
    return 0;
}

static int stack_open(struct inode *inode, struct file *file)
{
	return single_open(file, stack_show, inode->i_private);
}

static const struct file_operations stack_fops = {
	.open		= stack_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};


static __init int kernel_time_trace_init(void)
{
    struct noschedule_info *info = &nosched_info;
    
    printk("in kernel_time_trace_init\n");
    
    //在所有kernel支持的tracepoint上执行tracepoint_lookup回调函数，info为函数参数
    for_each_kernel_tracepoint(tracepoint_lookup, info);

    if (!is_tracepoint_lookup_success(info))
		return -ENODEV; 
    info->stack_trace = alloc_percpu(struct per_cpu_stack_trace);
	if (!info->stack_trace)
		return -ENOMEM;
    //debugfs文件系统中创建目录文件，用于用户空间的操作
    time_tracer = debugfs_create_dir("time_tracer", NULL);
    if(!time_tracer)
        goto free_cpu_buf;
    printk("lsg debug time tracer create ok\n");
    
    if(!debugfs_create_file("enable", 0644, time_tracer, NULL, &enable_fops))
        goto unregister_debugfs_time_tracer;
    if(!debugfs_create_file("duration", 0644, time_tracer, NULL, &duration_fops))
        goto unregister_debugfs_time_tracer;
    if(!debugfs_create_file("stack", 0644, time_tracer, NULL, &stack_fops))
        goto unregister_debugfs_time_tracer;
    return 0;
unregister_debugfs_time_tracer:
    debugfs_remove(time_tracer);
free_cpu_buf:
	free_percpu(info->stack_trace);
    return -ENOENT;
    
}


static __exit void kernel_time_trace_exit(void)
{
    if (trace_enable) 
    {
		trace_nosched_hrtimer_cancel();
		trace_nosched_unregister_tp();
		tracepoint_synchronize_unregister();
	}
    if(time_tracer)
        debugfs_remove_recursive(time_tracer);
	free_percpu(nosched_info.stack_trace);
}

module_init(kernel_time_trace_init);
module_exit(kernel_time_trace_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Liu Shiguang<lsg@idste.cn>");

