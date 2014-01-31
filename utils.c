#include "utils.h"

inline struct process_ids* get_process_ids()
{
	struct task_struct *atask;
	struct task_struct *ptask;
	struct process_ids *pids;

	pids = kmalloc(sizeof(struct process_ids), GFP_KERNEL);

	pids->uid = current_uid();
	pids->pid = current->pid;
	pids->audit = get_audit_id();

	ptask = find_task_by_vpid(pids->pid);
	pids->ppid = (long)(ptask->real_parent->pid);
	
	atask = find_task_by_vpid(pids->audit);
	if(atask != NULL && atask->real_parent != NULL) {
		pids->paudit = atask->real_parent->pid;
	}
	else {
		pids->paudit = -1;
	}

	return pids;
}

static inline void get_fs_pwd(struct fs_struct *fs, struct path *pwd)
{
	read_lock(&fs->lock);
	//spin_lock(&fs->lock);
	*pwd = fs->pwd;
	path_get(pwd);
	read_unlock(&fs->lock);
	//spin_unlock(&fs->lock);
}

inline long get_audit_id(void)
{
	return  pid_vnr(task_session(current));
}
 
struct log_path *find_path(void)
{
	struct log_path *lp;
	char *pp;
	struct dentry *de;
	struct path pwd;
	get_fs_pwd(current->fs, &pwd);	
	de = pwd.dentry;

	lp = kmalloc(sizeof(struct log_path), GFP_KERNEL);

	if(de == de->d_parent) {
		lp->mem = kmalloc(sizeof(char) * 2, GFP_KERNEL);
		lp->mem[0] = '/';
		lp->mem[1] = '\0';
		lp->name = lp->mem;
		return lp;
	}

	lp->mem = kmalloc(sizeof(char) * PATH_MAX, GFP_KERNEL);
	pp = lp->mem + PATH_MAX - 1;
	*pp = '\0';
	pp --;
	while(de != de->d_parent) {
		*pp = '/';
		pp -= de->d_name.len;
		memcpy(pp, de->d_name.name, de->d_name.len);
		pp --;
		de = de->d_parent;
	}
	*pp = '/';
	lp->name = pp;
	return lp; 
}

void disable_page_protection(long unsigned int value)
{
   asm volatile("mov %%cr0,%0" : "=r" (value));

   if (value & 0x00010000)
   {
      value &= ~0x00010000;
      asm volatile("mov %0,%%cr0": : "r" (value));
   }
}

void enable_page_protection(long unsigned int value)
{
   asm volatile("mov %%cr0,%0" : "=r" (value));

   if (!(value & 0x00010000))
   {
      value |= 0x00010000;
      asm volatile("mov %0,%%cr0": : "r" (value));
   }
}

long atoi2(const char *inputstring)
{
   long temp;
   char *end;
   const int base = 10;
   mm_segment_t old_fs;


   old_fs = get_fs();
   set_fs(KERNEL_DS);

   temp = simple_strtol(inputstring, &end, base);

   set_fs(old_fs);

   return temp;
}

#ifndef find_task_by_vpid
struct task_struct *find_task_by_vpid(pid_t vnr)
{
	struct pid *pid_struct;
	struct task_struct *task;
	pid_struct = find_get_pid(vnr);
	task = pid_task(pid_struct,PIDTYPE_PID);
	return task;
}
#endif
