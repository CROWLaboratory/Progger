#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/kthread.h>
#include <linux/fdtable.h>
#include <linux/spinlock.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/rcupdate.h>
#include <linux/crc16.h>
#include "syscalltypes.h"
#include "logformat.h"

MODULE_AUTHOR("Mark W");
MODULE_DESCRIPTION("Progger");
MODULE_LICENSE("GPL");

/* Input Parameters */
unsigned long SYSTABLE;
module_param(SYSTABLE, long, 0);

/* Global Variables */
void **sys_call_table;

/* System Calls */
asmlinkage long (*original_sys_open_call) (const char*, int, int);
asmlinkage long (*original_sys_close_call) (int);
asmlinkage long (*original_sys_rename_call) (const char*, const char*);
asmlinkage long (*original_sys_unlink_call) (const char*);
asmlinkage long (*original_sys_unlinkat_call) (int, const char *, int);
asmlinkage long (*original_sys_read_call) (unsigned int, char*, size_t);
asmlinkage long (*original_sys_write_call) (unsigned int, const char*, size_t);
asmlinkage long (*original_sys_writev_call) (unsigned long, const struct iovec __user *, unsigned long);
asmlinkage long (*original_sys_pwrite64_call) (unsigned int, const char __user *, size_t, loff_t);
asmlinkage long (*original_sys_dup2_call) (unsigned int, unsigned int);
asmlinkage long (*original_sys_dup_call) (unsigned int);
asmlinkage long (*original_sys_mkdir_call) (const char *, mode_t);
asmlinkage long (*original_sys_rmdir_call) (const char *);
asmlinkage long (*original_sys_symlink_call) (const char *, const char *);
asmlinkage long (*original_sys_link_call) (const char*, const char*);
asmlinkage long (*original_sys_linkat_call) (int, const char *, int, const char *, int);
asmlinkage long (*original_sys_chown_call) (const char*, uid_t, gid_t);
asmlinkage long (*original_sys_fchown_call) (int, uid_t, gid_t);
asmlinkage long (*original_sys_lchown_call) (const char*, uid_t, gid_t);
asmlinkage long (*original_sys_fchownat_call) (int, const char*, uid_t, gid_t, int);
asmlinkage long (*original_sys_chmod_call) (const char*, mode_t);
asmlinkage long (*original_sys_fchmod_call) (int, mode_t);
asmlinkage long (*original_sys_fchmodat_call) (int, const char*, mode_t, int);
asmlinkage long (*original_sys_sendfile_call) (int, int, off_t *, size_t);
asmlinkage long (*original_sys_connect_call) (int, struct sockaddr __user *, int);
asmlinkage long (*original_sys_accept_call) (int, struct sockaddr __user *, int *);
asmlinkage long (*original_sys_sendto_call) (int, const void *, size_t, int, const struct sockaddr *, int);
asmlinkage long (*original_sys_recvfrom_call) (int, const void *, size_t, int, const struct sockaddr *, int);
asmlinkage long (*original_sys_sendmsg_call) (int, const struct msghdr *, int); 
asmlinkage long (*original_sys_recvmsg_call) (int, const struct msghdr *, int); 
asmlinkage long (*original_sys_socket_call) (int, int, int);
asmlinkage long (*original_sys_pipe_call) (int[2]);
asmlinkage long (*original_sys_pipe2_call) (int[2], int);

/* 
 * Include all the functions. 
 * Split into multiple files to make everything cleaner and the files smaller.
 */ 
#include "utils.c"
#include "passwd.c"
#include "file_syscalls.c"
#include "socket_syscalls.c"

int init_module(void)
{
	printk(KERN_ALERT "Progger: module inserted\n");

	/* Get system table address */
	sys_call_table = (void*) SYSTABLE;

	/* Disable Page Protection so the table can be modified */
	disable_page_protection( (long unsigned int) sys_call_table);
	
	/* Change the system calls to our ones */
	original_sys_open_call = (void*)xchg(&sys_call_table[__NR_open], our_sys_open);
	original_sys_close_call = (void*)xchg(&sys_call_table[__NR_close], our_sys_close);
	original_sys_rename_call = (void*)xchg(&sys_call_table[__NR_rename], our_sys_rename);
	original_sys_unlink_call = (void*)xchg(&sys_call_table[__NR_unlink], our_sys_unlink);
	original_sys_unlinkat_call = (void*)xchg(&sys_call_table[__NR_unlinkat], our_sys_unlinkat);
	original_sys_write_call = (void*)xchg(&sys_call_table[__NR_write], our_sys_write);
	original_sys_writev_call = (void*)xchg(&sys_call_table[__NR_writev], our_sys_writev);
	original_sys_pwrite64_call = (void*)xchg(&sys_call_table[__NR_pwrite64], our_sys_pwrite64);
	original_sys_dup_call = (void*)xchg(&sys_call_table[__NR_dup], our_sys_dup);
	original_sys_dup2_call = (void*)xchg(&sys_call_table[__NR_dup2], our_sys_dup2);
	original_sys_read_call = (void*)xchg(&sys_call_table[__NR_read], our_sys_read);
	original_sys_mkdir_call = (void*)xchg(&sys_call_table[__NR_mkdir], our_sys_mkdir);
	original_sys_rmdir_call = (void*)xchg(&sys_call_table[__NR_rmdir], our_sys_rmdir);
	original_sys_symlink_call = (void*)xchg(&sys_call_table[__NR_symlink], our_sys_symlink);
	original_sys_link_call = (void*)xchg(&sys_call_table[__NR_link], our_sys_link);
	original_sys_linkat_call = (void*)xchg(&sys_call_table[__NR_linkat], our_sys_linkat);
	original_sys_chown_call = (void*)xchg(&sys_call_table[__NR_chown], our_sys_chown);
	original_sys_fchown_call = (void*)xchg(&sys_call_table[__NR_fchown], our_sys_fchown);
	original_sys_lchown_call = (void*)xchg(&sys_call_table[__NR_lchown], our_sys_lchown);
	original_sys_fchownat_call = (void*)xchg(&sys_call_table[__NR_fchownat], our_sys_fchownat);
	original_sys_chmod_call = (void*)xchg(&sys_call_table[__NR_chmod], our_sys_chmod);
	original_sys_fchmod_call = (void*)xchg(&sys_call_table[__NR_fchmod], our_sys_fchmod);
	original_sys_fchmodat_call = (void*)xchg(&sys_call_table[__NR_fchmodat], our_sys_fchmodat);
	original_sys_sendfile_call = (void*)xchg(&sys_call_table[__NR_sendfile], our_sys_sendfile);	
	original_sys_connect_call = (void*)xchg(&sys_call_table[__NR_connect], our_sys_connect);
	original_sys_accept_call = (void*)xchg(&sys_call_table[__NR_accept], our_sys_accept);
	original_sys_sendto_call = (void*)xchg(&sys_call_table[__NR_sendto], our_sys_sendto);
	original_sys_recvfrom_call = (void*)xchg(&sys_call_table[__NR_recvfrom], our_sys_recvfrom);
	original_sys_sendmsg_call = (void*)xchg(&sys_call_table[__NR_sendmsg], our_sys_sendmsg);
	original_sys_recvmsg_call = (void*)xchg(&sys_call_table[__NR_recvmsg], our_sys_recvmsg);
	original_sys_socket_call = (void*)xchg(&sys_call_table[__NR_socket], our_sys_socket);
	original_sys_pipe_call = (void*)xchg(&sys_call_table[__NR_pipe], our_sys_pipe);
	original_sys_pipe2_call = (void*)xchg(&sys_call_table[__NR_pipe2], our_sys_pipe2);
	
	/* Renable Page Protection */
	enable_page_protection( (long unsigned int) sys_call_table);

	return 0;
}

void cleanup_module(void)
{
	printk(KERN_ALERT "Progger: module removed\n");
	
	/* Disable Page Protection so the table can be modified */
	disable_page_protection( (long unsigned int) sys_call_table);

	/* Restore original system calls */	
	sys_call_table[__NR_open] = original_sys_open_call;
	sys_call_table[__NR_close] = original_sys_close_call;
	sys_call_table[__NR_rename] = original_sys_rename_call;
	sys_call_table[__NR_unlink] = original_sys_unlink_call;
	sys_call_table[__NR_unlinkat] = original_sys_unlinkat_call;
	sys_call_table[__NR_write] = original_sys_write_call;
	sys_call_table[__NR_writev] = original_sys_writev_call;
	sys_call_table[__NR_pwrite64] = original_sys_pwrite64_call;
	sys_call_table[__NR_dup] = original_sys_dup_call;
	sys_call_table[__NR_dup2] = original_sys_dup2_call;
	sys_call_table[__NR_read] = original_sys_read_call;
	sys_call_table[__NR_mkdir] = original_sys_mkdir_call;
	sys_call_table[__NR_rmdir] = original_sys_rmdir_call;
	sys_call_table[__NR_symlink] = original_sys_symlink_call;
	sys_call_table[__NR_link] = original_sys_link_call;
	sys_call_table[__NR_linkat] = original_sys_linkat_call;
	sys_call_table[__NR_chown] = original_sys_chown_call;
	sys_call_table[__NR_fchown] = original_sys_fchown_call;
	sys_call_table[__NR_lchown] = original_sys_lchown_call;
	sys_call_table[__NR_fchownat] = original_sys_fchownat_call;
	sys_call_table[__NR_chmod] = original_sys_chmod_call;
	sys_call_table[__NR_fchmod] = original_sys_fchmod_call;
	sys_call_table[__NR_fchmodat] = original_sys_fchmodat_call;
	sys_call_table[__NR_sendfile] = original_sys_sendfile_call;
	sys_call_table[__NR_connect] = original_sys_connect_call;
	sys_call_table[__NR_accept] = original_sys_accept_call;
	sys_call_table[__NR_sendto] = original_sys_sendto_call;
	sys_call_table[__NR_recvfrom] = original_sys_recvfrom_call;
	sys_call_table[__NR_sendmsg] = original_sys_sendmsg_call;
	sys_call_table[__NR_recvmsg] = original_sys_recvmsg_call;
	sys_call_table[__NR_socket] = original_sys_socket_call;
	sys_call_table[__NR_pipe] = original_sys_pipe_call;
	sys_call_table[__NR_pipe2] = original_sys_pipe2_call;

	/* Renable Page Protection */
	enable_page_protection( (long unsigned int) sys_call_table);

	/* Clean Up */
	cleanup_passwd_entries();
}
