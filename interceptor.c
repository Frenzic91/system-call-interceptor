#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/unistd.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/syscalls.h>
#include "interceptor.h"


MODULE_DESCRIPTION("Malicious Logger");
MODULE_AUTHOR("Sandi Milicevic");
MODULE_LICENSE("GPL");

//----- System Call Table Stuff ------------------------------------
/* Symbol that allows access to the kernel system call table */
extern void* sys_call_table[];

/* The sys_call_table is read-only => must make it RW before replacing a syscall */
void set_addr_rw(unsigned long addr) {

	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}

/* Restores the sys_call_table as read-only */
void set_addr_ro(unsigned long addr) {

	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	pte->pte = pte->pte &~_PAGE_RW;

}
//-------------------------------------------------------------


//----- Data structures and bookkeeping -----------------------
/**
 * This block contains the data structures needed for keeping track of
 * intercepted system calls (including their original calls), pid monitoring
 * synchronization on shared data, etc.
 * It's highly unlikely that you will need any globals other than these.
 */

/* List structure - each intercepted syscall may have a list of monitored pids */
struct pid_list {
	pid_t pid;
	struct list_head list;
};


/* Store info about intercepted/replaced system calls */
typedef struct {

	/* Original system call */
	asmlinkage long (*f)(struct pt_regs);

	/* Status: 1=intercepted, 0=not intercepted */
	int intercepted;

	/* Are any PIDs being monitored for this syscall? */
	int monitored;	
	/* List of monitored PIDs */
	int listcount;
	struct list_head my_list;
} mytable;

/* An entry for each system call */
mytable table[NR_syscalls+1];

/* Access to the table and pid lists must be synchronized */
spinlock_t pidlist_lock = SPIN_LOCK_UNLOCKED;
spinlock_t calltable_lock = SPIN_LOCK_UNLOCKED;
//-------------------------------------------------------------


//----------LIST OPERATIONS------------------------------------
/**
 * These operations are meant for manipulating the list of pids 
 * Nothing to do here, but please make sure to read over these functions 
 * to understand their purpose, as you will need to use them!
 */

/**
 * Add a pid to a syscall's list of monitored pids. 
 * Returns -ENOMEM if the operation is unsuccessful.
 */
static int add_pid_sysc(pid_t pid, int sysc)
{
	struct pid_list *ple=(struct pid_list*)kmalloc(sizeof(struct pid_list), GFP_KERNEL);

	if (!ple)
		return -ENOMEM;

	INIT_LIST_HEAD(&ple->list);
	ple->pid=pid;

	list_add(&ple->list, &(table[sysc].my_list));
	table[sysc].listcount++;

	return 0;
}

/**
 * Remove a pid from a system call's list of monitored pids.
 * Returns -EINVAL if no such pid was found in the list.
 */
static int del_pid_sysc(pid_t pid, int sysc)
{
	struct list_head *i;
	struct pid_list *ple;

	list_for_each(i, &(table[sysc].my_list)) {

		ple=list_entry(i, struct pid_list, list);
		if(ple->pid == pid) {

			list_del(i);
			kfree(ple);

			table[sysc].listcount--;
			/* If there are no more pids in sysc's list of pids, then
			 * stop the monitoring only if it's not for all pids (monitored=2) */
			if(table[sysc].listcount == 0 && table[sysc].monitored == 1) {
				table[sysc].monitored = 0;
			}

			return 0;
		}
	}

	return -EINVAL;
}

/**
 * Remove a pid from all the lists of monitored pids (for all intercepted syscalls).
 * Returns -1 if this process is not being monitored in any list.
 */
static int del_pid(pid_t pid)
{
	struct list_head *i, *n;
	struct pid_list *ple;
	int ispid = 0, s = 0;

	for(s = 1; s < NR_syscalls; s++) {

		list_for_each_safe(i, n, &(table[s].my_list)) {

			ple=list_entry(i, struct pid_list, list);
			if(ple->pid == pid) {

				list_del(i);
				ispid = 1;
				kfree(ple);

				table[s].listcount--;
				/* If there are no more pids in sysc's list of pids, then
				 * stop the monitoring only if it's not for all pids (monitored=2) */
				if(table[s].listcount == 0 && table[s].monitored == 1) {
					table[s].monitored = 0;
				}
			}
		}
	}

	if (ispid) return 0;
	return -1;
}

/**
 * Clear the list of monitored pids for a specific syscall.
 */
static void destroy_list(int sysc) {

	struct list_head *i, *n;
	struct pid_list *ple;

	list_for_each_safe(i, n, &(table[sysc].my_list)) {

		ple=list_entry(i, struct pid_list, list);
		list_del(i);
		kfree(ple);
	}

	table[sysc].listcount = 0;
	table[sysc].monitored = 0;
}

/**
 * Check if two pids have the same owner - useful for checking if a pid 
 * requested to be monitored is owned by the requesting process.
 * Remember that when requesting to start monitoring for a pid, only the 
 * owner of that pid is allowed to request that.
 */
static int check_pid_from_list(pid_t pid1, pid_t pid2) {

	struct task_struct *p1 = pid_task(find_vpid(pid1), PIDTYPE_PID);
	struct task_struct *p2 = pid_task(find_vpid(pid2), PIDTYPE_PID);
	if(p1->real_cred->uid != p2->real_cred->uid)
		return -EPERM;
	return 0;
}

/**
 * Check if a pid is already being monitored for a specific syscall.
 * Returns 1 if it already is, or 0 if pid is not in sysc's list.
 */
static int check_pid_monitored(int sysc, pid_t pid) {

	struct list_head *i;
	struct pid_list *ple;

	list_for_each(i, &(table[sysc].my_list)) {

		ple=list_entry(i, struct pid_list, list);
		if(ple->pid == pid) 
			return 1;
		
	}
	return 0;	
}
//----------------------------------------------------------------

//----- Intercepting exit_group ----------------------------------
/**
 * Since a process can exit without its owner specifically requesting
 * to stop monitoring it, we must intercept the exit_group system call
 * so that we can remove the exiting process's pid from *all* syscall lists.
 */  

/** 
 * Stores original exit_group function - after all, we must restore it 
 * when our kernel module exits.
 */
void (*orig_exit_group)(int);

/**
 * Our custom exit_group system call.
 */
void my_exit_group(int status)
{

spin_lock(&calltable_lock);
spin_lock(&pidlist_lock);

// remove pid of exiting process from pidlist of all system calls
del_pid(current->pid);

spin_unlock(&pidlist_lock);
spin_unlock(&calltable_lock);

// call the original exit group function
orig_exit_group(status);

}
//----------------------------------------------------------------



/** 
 * This is the generic interceptor function.
 * It should just log a message and call the original syscall.
 */
asmlinkage long interceptor(struct pt_regs reg) {
	// declarations at top by ISO C90 Standard
	long rc;

	spin_lock(&calltable_lock);
	spin_lock(&pidlist_lock);

	// the two cases are identical, just represented differently
	if ((table[reg.ax].monitored == 1 && check_pid_monitored(reg.ax, current->pid) == 1) ||
		(table[reg.ax].monitored == 2 && check_pid_monitored(reg.ax, current->pid) == 0)) {

		log_message(current->pid, reg.ax, reg.bx, reg.cx, reg.dx, reg.si, reg.di, reg.bp);
	}

	// call original system call after logging
	rc = table[reg.ax].f(reg);

	spin_unlock(&pidlist_lock);
	spin_unlock(&calltable_lock);

	return rc; 
}

/**
 * My system call - this function is called whenever a user issues a MY_CUSTOM_SYSCALL system call.
 * When that happens, the parameters for this system call indicate one of 4 actions/commands:
 *      - REQUEST_SYSCALL_INTERCEPT to intercept the 'syscall' argument
 *      - REQUEST_SYSCALL_RELEASE to de-intercept the 'syscall' argument
 *      - REQUEST_START_MONITORING to start monitoring for 'pid' whenever it issues 'syscall' 
 *      - REQUEST_STOP_MONITORING to stop monitoring for 'pid'
 *      For the last two, if pid=0, that translates to "all pids".
 *
 * Note: didn't have time to refactor/modularize the function so it's pretty gigantic -__-
 */
asmlinkage long my_syscall(int cmd, int syscall, int pid) {
	
	// invalid system call
	if (syscall == MY_CUSTOM_SYSCALL || syscall < 1 || syscall > NR_syscalls) {
		return -EINVAL;
	}

	// request to intercept
	if (cmd == REQUEST_SYSCALL_INTERCEPT) {
		// must be root
		if (current_uid() != 0) {
			return -EPERM;
		}
		spin_lock(&calltable_lock);

		if (table[syscall].intercepted) {
			spin_unlock(&calltable_lock);
			return -EBUSY;
		}

		spin_unlock(&calltable_lock);


		spin_lock(&calltable_lock);

		/* hijack system call */
		// store original syscall fp
		table[syscall].f = sys_call_table[syscall];
		table[syscall].intercepted = 1;

		// replace with our own syscall fp
		set_addr_rw((unsigned long) sys_call_table);
		sys_call_table[syscall] = interceptor;
		set_addr_ro((unsigned long) sys_call_table);

		spin_unlock(&calltable_lock);
		
		return 0;
		
	}
	// request to release
	else if (cmd == REQUEST_SYSCALL_RELEASE) {
		// must be root
		if (current_uid() != 0) {
			return -EPERM;
		}
		spin_lock(&calltable_lock);

		if (!table[syscall].intercepted) {
			spin_unlock(&calltable_lock);
			return -EINVAL;
		}

		spin_unlock(&calltable_lock);


		spin_lock(&calltable_lock);

		/* restore original system call */
		set_addr_rw((unsigned long) sys_call_table);
		sys_call_table[syscall] = table[syscall].f;
		set_addr_ro((unsigned long) sys_call_table);

		table[syscall].f = NULL;
		table[syscall].intercepted = 0;

		spin_lock(&pidlist_lock);

		// system call released, stop monitoring all pids
		destroy_list(syscall);
		INIT_LIST_HEAD(&(table[syscall].my_list));

		spin_unlock(&pidlist_lock);
		spin_unlock(&calltable_lock);
		
		return 0;
	}
	// request to start monitoring pid(s) for syscall
	else if (cmd == REQUEST_START_MONITORING) {
		// declarations at top by ISO C90 Standard
		int intercepted;

		// invalid pid
		if (pid != 0 && pid_task(find_vpid(pid), PIDTYPE_PID) == NULL) {
			printk(KERN_INFO "Invalid pid");
			return -EINVAL;
		}

		spin_lock(&calltable_lock);

		intercepted = table[syscall].intercepted; 
		if (!intercepted) {
			spin_unlock(&calltable_lock);
			printk(KERN_INFO "Tried to monitor when syscall not yet intercepted");
			return -EINVAL;
		}

		spin_unlock(&calltable_lock);

		// monitor specific pid
		if (pid != 0) {
			// current process must own pid
			if (check_pid_from_list(current->pid, pid) == -EPERM) {
				return -EPERM;
			}

			// lock will be released in one of the if-else branches
			spin_lock(&calltable_lock);
			// no pids monitored yet
			if (table[syscall].monitored == 0) {

				spin_lock(&pidlist_lock);

				if (add_pid_sysc(pid, syscall) == -ENOMEM) {
					spin_unlock(&pidlist_lock);
					spin_unlock(&calltable_lock);
					return -ENOMEM;
				}
				table[syscall].monitored = 1;

				spin_unlock(&pidlist_lock);
				spin_unlock(&calltable_lock);
				return 0;

			// pids are being monitored via whitelist
			} else if (table[syscall].monitored == 1) {

				spin_lock(&pidlist_lock);

				if (check_pid_monitored(syscall, pid) == 1) {
					spin_unlock(&pidlist_lock);
					spin_unlock(&calltable_lock);
					return -EBUSY;
				}
				if (add_pid_sysc(pid, syscall) == -ENOMEM) {
					spin_unlock(&pidlist_lock);
					spin_unlock(&calltable_lock);
					return -ENOMEM;
				}

				spin_unlock(&pidlist_lock);
				spin_unlock(&calltable_lock);
				return 0;

			// pids are being monitored via blacklist
			} else {

				spin_lock(&pidlist_lock);

				if (check_pid_monitored(syscall, pid) == 0) {
					spin_unlock(&pidlist_lock);
					spin_unlock(&calltable_lock);
					return -EBUSY;
				}
				if (del_pid_sysc(pid, syscall) == -ENOMEM) {
					spin_unlock(&pidlist_lock);
					spin_unlock(&calltable_lock);
					return -ENOMEM;
				}

				spin_unlock(&pidlist_lock);
				spin_unlock(&calltable_lock);
				return 0;
			}

		// request to start monitoring ALL pids
		} else if (pid == 0) {
			// user must be root
			if (current_uid() != 0) {
				return -EPERM;
			}

			spin_lock(&calltable_lock);
			spin_lock(&pidlist_lock);

			/* create a blacklist */
			destroy_list(syscall);

			INIT_LIST_HEAD(&(table[syscall].my_list));
			table[syscall].monitored = 2;

			spin_unlock(&pidlist_lock);
			spin_unlock(&calltable_lock);

			return 0;
		}
	}
	// request to stop monitoring
	else if (cmd == REQUEST_STOP_MONITORING) {
		// declarations at top by ISO C90 Standard
		int intercepted;

		// invalid pid
		if (pid != 0 && pid_task(find_vpid(pid), PIDTYPE_PID) == NULL) {
			return -EINVAL;
		}

		spin_lock(&calltable_lock);

		intercepted = table[syscall].intercepted; 
		if (!intercepted) {
			spin_unlock(&calltable_lock);
			return -EINVAL;
		}

		spin_unlock(&calltable_lock);

		// stop monitoring specific pid
		if (pid != 0) {
			// pid must be owned by current process
			if (check_pid_from_list(current->pid, pid) == -EPERM) {
				return -EPERM;
			}

			// lock will be released in one of the if-else branches
			spin_lock(&calltable_lock);
			// no pids monitored, invalid request
			if (table[syscall].monitored == 0) {
				spin_unlock(&calltable_lock);
				return -EINVAL;

			// whitelist maintained to track monitored pids
			} else if (table[syscall].monitored == 1) {

				spin_lock(&pidlist_lock);

				if (check_pid_monitored(syscall, pid) == 1) {
					if (del_pid_sysc(pid, syscall) == -EINVAL) {

						spin_unlock(&pidlist_lock);
						spin_unlock(&calltable_lock);
						return -EINVAL;
					}

					spin_unlock(&pidlist_lock);
					spin_unlock(&calltable_lock);
					return 0;

				} else {
					spin_unlock(&pidlist_lock);
					spin_unlock(&calltable_lock);

					return -EINVAL;
				}
			// blacklist maintained to track monitored pids, conditions are inverted
			} else {
				spin_lock(&pidlist_lock);

				if (check_pid_monitored(syscall, pid) == 0) {
					if (add_pid_sysc(syscall, pid) == -ENOMEM) {

						spin_unlock(&pidlist_lock);
						spin_unlock(&calltable_lock);
						return -ENOMEM;
					}
					spin_unlock(&pidlist_lock);
					spin_unlock(&calltable_lock);

					return 0;

				} else {
					spin_unlock(&pidlist_lock);
					spin_unlock(&calltable_lock);
					return -EINVAL;
				}
			}
		// request to stop monitoring ALL pids
		} else if (pid == 0) {
			if (current_uid() != 0) {
				return -EPERM;
			}
			spin_lock(&calltable_lock);
			spin_lock(&pidlist_lock);

			destroy_list(syscall);

			INIT_LIST_HEAD(&(table[syscall].my_list));

			spin_unlock(&pidlist_lock);
			spin_unlock(&calltable_lock);
			
			return 0;
		}
	}
	// invalid command
	else {
		return -EINVAL; 
	}
	// prevent compiler warnings due to ISO C90 Standard
	return 0;
}

// stores the original system call function pointer located at sys_call_table[0]
long (*orig_custom_syscall)(void);


/**
 * Module initialization
 */
static int init_function(void) {
	// declarations at top by ISO C90 Standard
	int i;

	printk(KERN_INFO "Initializing hijack module...");

	spin_lock(&calltable_lock);

	// save original function pointers
	orig_custom_syscall = sys_call_table[MY_CUSTOM_SYSCALL];
	orig_exit_group = sys_call_table[__NR_exit_group];
	set_addr_rw((unsigned long) sys_call_table);
	// replace original function pointers with our own
	sys_call_table[MY_CUSTOM_SYSCALL] = my_syscall;
	sys_call_table[__NR_exit_group] = my_exit_group;
	set_addr_ro((unsigned long) sys_call_table);
	
	/* initialize meta data structures for each syscall */

	for (i=0; i<=NR_syscalls; i++) {
		table[i].intercepted = 0;
		table[i].monitored = 0;
		table[i].listcount = 0;
		
		spin_lock(&pidlist_lock);
		INIT_LIST_HEAD(&table[i].my_list);
		spin_unlock(&pidlist_lock);
	}
	spin_unlock(&calltable_lock);

	return 0;
}

/**
 * Module exits
 */
static void exit_function(void)
{        
	/* Note: I did not free memory reserved for pidlist since del_pid is called
	inside my_exit_group which is called when each process exits. I am assuming
	that before the kernel module can exit all processes must be terminated first
	by the kernel and therefore del_pid will be called for each pid leading to
	all of the memory being freed that way. My assumption is probably wrong but 
	that's my reasoning anyway. Please correct me if I'm wrong thanks! */

	spin_lock(&calltable_lock);

	set_addr_rw((unsigned long) sys_call_table);
	sys_call_table[__NR_exit_group] = orig_exit_group;
	sys_call_table[MY_CUSTOM_SYSCALL] = orig_custom_syscall;
	set_addr_ro((unsigned long) sys_call_table);

	spin_unlock(&calltable_lock);

}

module_init(init_function);
module_exit(exit_function);

