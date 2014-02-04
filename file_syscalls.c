/*

 This file is part of Progger - Logging Provenance for Security

 Copyright (c) 2013, 2014     Mark A. Will <maw41@waikato.ac.nz>
                              CROW - Cybersecurity Researchers of Waikato

 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 	* Redistributions of source code must retain the above copyright
 		notice, this list of conditions and the following disclaimer.
 	* Redistributions in binary form must reproduce the above copyright
 		notice, this list of conditions and the following disclaimer in the
 		documentation and/or other materials provided with the distribution.
 	* Neither the name of the organization nor the
	  names of its contributors may be used to endorse or promote products
 		derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL ANTHONY M. BLAKE BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "file_syscalls.h"

int is_relevant_file(const char* filename, long *uid, long *gid)
{
	return 1;
}


int is_log_file(const char* filename)
{
	if(	strlen(filename) == 20 &&	
		filename[0] == '/' &&
		filename[1] == 'v' &&
		filename[2] == 'a' &&
		filename[3] == 'r' &&
		filename[4] == '/' &&
		filename[5] == 'l' &&
		filename[6] == 'o' &&
		filename[7] == 'g' &&
		filename[8] == '/' &&
		filename[9] == 'p' &&
		filename[10] == 'r' &&
		filename[11] == 'o' &&
		filename[12] == 'g' &&
		filename[13] == 'g' &&
		filename[14] == 'e' &&
		filename[15] == 'r' &&
		filename[16] == '.' &&
		filename[17] == 'l' &&
		filename[18] == 'o' &&
		filename[19] == 'g')
	{
		return 1;
	} 
	else 
	{
		return 0;
	}
}

asmlinkage long our_sys_open(const char* file, int flags, int mode)
{
	long fd = 0;
	long uid, gid;
	struct log_path *p; 
	struct passwd_entry *pe = NULL;
	struct process_ids *pids;
	struct task_struct *ptask;
	int is_log;
	int type; 

	type = SYSCALL_OPEN;
	is_log = is_log_file(file); 
	//if (is_relevant_file(file, &uid, &gid) == 1)
	if(is_log == 0) 
	{
		if((flags & O_CREAT) > 0) {
			flags -= O_CREAT;
			fd = original_sys_open_call(file, flags, mode);
			flags += O_CREAT;
			if(fd < 0) {
				type = SYSCALL_CREAT;
				fd = original_sys_open_call(file, flags, mode);
				if(fd < 0) return fd; //Error opening file	
			}
		} 
		else {
			fd = original_sys_open_call(file, flags, mode);
			if(fd < 0) return fd; //Error opening file	
		}

		pids = get_process_ids();
		pe = get_passwd_entry(pids->uid);
		p = find_path();
		ptask = find_task_by_vpid(pids->pid);
		LOG_OPEN(type, pe->username, pids->pid, pids->ppid, pids->audit, pids->paudit, ptask->comm, file, p->name, flags, mode, fd);
		kfree(p);
		kfree(pids);
	} 
	else
	{
		//TODO: check process if for rsyslog
		fd = original_sys_open_call(file, flags, mode);
	}
	return fd;
}

asmlinkage long our_sys_close(unsigned int fd)
{
	long result;
	struct file *f;
	struct passwd_entry *pe; 
	struct task_struct *atask;
	int is_sock;
	struct process_ids *pids;
	char *test = "Hello World, this is meeeee";	
	u16 crc;

	result = original_sys_close_call(fd);
	if(result < 0 ) return result;	

	pids = get_process_ids();
	pe = get_passwd_entry(pids->uid); 
	atask = find_task_by_vpid(pids->audit);

	is_sock = 0;
	rcu_read_lock();
		f = fcheck_files(current->files, fd);
		if(f != NULL && ((f->f_path.dentry->d_inode->i_mode) & S_IFMT) == S_IFSOCK) is_sock = 1; 
	rcu_read_unlock();

	if(atask != NULL && atask->cred != NULL && atask->cred->euid != 0) { 
		if(is_sock) LOG_S_CLOSE(SYSCALL_CLOSE, pe->username, pids->pid, pids->ppid, pids->audit, pids->paudit, fd);
		else LOG_CLOSE(SYSCALL_CLOSE, pe->username, pids->pid, pids->ppid, pids->audit, pids->paudit, fd);

		//crc = 0;
		//crc = crc16(crc, test, strlen(test));
		//crc = crc16(crc, (char *)(pids->uid), 4);
		//printk(KERN_INFO "Progger: CRC of '%d' is %d\n", pids->uid, crc);
	}
	kfree(pids);
	return result;
}

asmlinkage long our_sys_rename(const char* oldfile, const char* newfile) 
{
	struct log_path *p;
	long euid, pid, ppid;
	long audit, paudit, result;
	struct passwd_entry *pe;
	struct task_struct *atask;
	struct task_struct *ptask;

	result = original_sys_rename_call(oldfile, newfile);
	if(result < 0) return result;

	euid = current_uid();
	pe = get_passwd_entry(euid); 
	pid = current->pid;
	audit = get_audit_id();
	ptask = find_task_by_vpid(pid);
	ppid = (long)(ptask->real_parent->pid);

	atask = find_task_by_vpid(audit);
	if(atask != NULL && atask->real_parent != NULL) {
		paudit = atask->real_parent->pid;
	}
	else {
		paudit = -1;
	}
	if(euid > 0 && pe != NULL) {
		p = find_path();
		LOG_RENAME(SYSCALL_MOVE, pe->username, pid, ppid, audit, paudit, ptask->comm, oldfile, newfile, p->name);
		kfree(p);
	}
	return result;
}

asmlinkage long our_sys_unlink(const char* file) 
{
	long result = 0;
	long uid, gid;
	long pid, p_uid, ppid;
	long audit, paudit;
	struct log_path *p; 
	struct passwd_entry *pe = NULL;
	struct task_struct *atask;
	struct task_struct *ptask;
	
	if (is_relevant_file(file, &uid, &gid) == 1)
	{
		result = original_sys_unlink_call(file);
		if(result >= 0) {
			pid = current->pid;
			p_uid = current_uid();
			pe = get_passwd_entry(p_uid);
			ptask = find_task_by_vpid(pid);
			ppid = (long)(ptask->real_parent->pid);
			audit = get_audit_id();
			p = find_path();
			atask = find_task_by_vpid(audit);
			if(atask != NULL && atask->real_parent != NULL) {
				paudit = atask->real_parent->pid;
			}
			else {
				paudit = -1;
			}
			LOG_UNLINK(SYSCALL_UNLINK, pe->username, pid, ppid, audit, paudit, ptask->comm, file, p->name);
		}	
	}
	else {
		result = original_sys_unlink_call(file);
	}
	return result;
}

asmlinkage long our_sys_unlinkat(int dirfd, const char* file, int flags) 
{
	long result = 0;
	long uid, gid;
	long pid, ppid, p_uid;
	long audit, paudit;
	struct log_path *p; 
	struct passwd_entry *pe = NULL;
	struct task_struct *atask;
	struct task_struct *ptask;

	if (is_relevant_file(file, &uid, &gid) == 1)
	{
		result = original_sys_unlinkat_call(dirfd, file, flags);
		
		if(result >= 0) {
			pid = current->pid;
			p_uid = current_uid();
			pe = get_passwd_entry(p_uid);
			ptask = find_task_by_vpid(pid);
			ppid = (long)(ptask->real_parent->pid);
			audit = get_audit_id();
			p = find_path();
			atask = find_task_by_vpid(audit);
			if(atask != NULL && atask->real_parent != NULL) {
				paudit = atask->real_parent->pid;
			}
			else {
				paudit = -1;
			}
			LOG_UNLINKAT(SYSCALL_UNLINK, pe->username, pid, ppid, audit, paudit, ptask->comm, file, p->name, dirfd, flags);
		}
	}
	else {
		result = original_sys_unlinkat_call(dirfd, file, flags);
	}

	return result;
}

asmlinkage long our_sys_dup2(unsigned int oldfd, unsigned int newfd)
{
	long uid, audit, paudit;
	long pid, ppid;
	long result;
	struct passwd_entry *pe = NULL;
	struct task_struct *atask;
	struct task_struct *ptask;

	result = original_sys_dup2_call(oldfd, newfd);
	if(result < 0) return result;
	
	uid = current_uid();
	audit = get_audit_id();
	pid = current->pid;
	pe = get_passwd_entry(uid);
	ptask = find_task_by_vpid(pid);
	ppid = (long)(ptask->real_parent->pid);
	atask = find_task_by_vpid(audit);
	if(atask != NULL && atask->real_parent != NULL) {
		paudit = atask->real_parent->pid;
	}
	else {
		paudit = -1;
	}
	LOG_DUP2(SYSCALL_DUP2, pe->username, pid, ppid, audit, paudit, oldfd, newfd);

	return result;
}

asmlinkage long our_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
	struct file *f;
	struct passwd_entry *pe;
	char *hexdata;
	char *p_hexdata;
	unsigned int value;
	int i;
	long offset;
	char *data;
	struct task_struct *atask;
	int is_sock;
	struct process_ids *pids;

	pids = get_process_ids();

	atask = find_task_by_vpid(pids->audit);

	if(atask != NULL && atask->cred != NULL && atask->cred->euid != 0) { 
		pe = get_passwd_entry(pids->uid);
		
		data = kmalloc((count + 1) * sizeof(char), GFP_KERNEL);
		memcpy(data, buf, count + 1);
		data[count] = '\0';

		is_sock = 0;
		/* Get file offset */
		rcu_read_lock();
		f = fcheck_files(current->files, fd);
		if(f) { 
			offset = f->f_pos;
			if(((f->f_path.dentry->d_inode->i_mode) & S_IFMT) == S_IFSOCK) is_sock = 1; 
		}
		else { 
			offset = 0;
		}
		rcu_read_unlock();
	
		hexdata = kmalloc((count + 1) * 2 * sizeof(char), GFP_KERNEL);
		p_hexdata = hexdata;
		for(i = 0; i < count; i++) {
			value = data[i];
			value = value & 255;
			sprintf(hexdata + (i * 2), "%02X", value);
		}
		hexdata[count * 2] = '\0';

		if(is_sock) LOG_S_RDWR(SYSCALL_WRITE, pe->username, pids->pid, pids->ppid, pids->audit, pids->paudit, fd, offset, hexdata);
		else LOG_RDWR(SYSCALL_WRITE, pe->username, pids->pid, pids->ppid, pids->audit, pids->paudit, fd, offset, hexdata);
	
		kfree(hexdata);
		kfree(data);
	}
	kfree(pids);
	return original_sys_write_call(fd, buf, count);
}

asmlinkage long our_sys_read(unsigned int fd, char __user *buf, size_t count)
{
	struct file *f;
	long result;
	struct passwd_entry *pe;
	char *hexdata;
	char *p_hexdata;
	unsigned int value;
	int i;
	long offset;
	char *data;
	struct task_struct *atask;
	char *username;
	int is_sock;
	struct process_ids *pids;

	pids = get_process_ids();
	atask = find_task_by_vpid(pids->audit);

	if(atask != NULL && atask->cred != NULL && atask->cred->euid != 0) { 
	
		if(pids->uid != 0) {
			pe = get_passwd_entry(pids->uid);
			username = pe->username;
		}
		else {
			pe = get_passwd_entry(atask->cred->euid);
			username = pe->username_root;
		}	

		is_sock = 0;
		/* Get file offset */
		rcu_read_lock();
		f = fcheck_files(current->files, fd);
		if(f) { 
			offset = f->f_pos;
			if(((f->f_path.dentry->d_inode->i_mode) & S_IFMT) == S_IFSOCK) is_sock = 1; 
		}
		else { 
			offset = 0;
		}
		rcu_read_unlock();
	
		result = original_sys_read_call(fd, buf, count);
		count = (size_t) result;
	
		if(result > 0) {	
			data = kmalloc((count + 1) * sizeof(char), GFP_KERNEL);
			memcpy(data, buf, count + 1);
			data[count] = '\0';

			hexdata = kmalloc((count + 1) * 2 * sizeof(char), GFP_KERNEL);
			p_hexdata = hexdata;
			for(i = 0; i < count; i++) {
				value = data[i];
				value = value & 255;
				sprintf(hexdata + (i * 2), "%02X", value);
			}
			hexdata[count * 2] = '\0';

			if(is_sock) LOG_S_RDWR(SYSCALL_READ, pe->username, pids->pid, pids->ppid, pids->audit, pids->paudit, fd, offset, hexdata);
			else LOG_RDWR(SYSCALL_READ, pe->username, pids->pid, pids->ppid, pids->audit, pids->paudit, fd, offset, hexdata);

			kfree(hexdata);
			kfree(data);
		}
	}
	else {
		result = original_sys_read_call(fd, buf, count);
	}
	kfree(pids);
	return result;
}

asmlinkage long our_sys_mkdir(const char *pathname, mode_t mode)
{
	long euid, result;
	long audit, pid;
	struct passwd_entry *pe;
	struct log_path *p;
	result = original_sys_mkdir_call(pathname, mode);

	if(result >= 0) {
		euid = current_uid();
		audit = get_audit_id();
		pid = current->pid;
		pe = get_passwd_entry(euid);
		p = find_path();
		LOG_MKDIR(SYSCALL_MKDIR, pe->username, pid, audit, pathname, p->name, mode);
		kfree(p);	
	}
	
	return result;
}

asmlinkage long our_sys_rmdir(const char *pathname)
{
	long euid, result;
	long audit, pid;
	struct passwd_entry *pe;
	struct log_path *p;
	result = original_sys_rmdir_call(pathname);

	if(result >= 0) {
		euid = current_uid();
		audit = get_audit_id();
		pid = current->pid;
		pe = get_passwd_entry(euid);
		p = find_path();
		LOG_RMDIR(SYSCALL_RMDIR, pe->username, pid, audit, pathname, p->name);
		kfree(p);	
	}
	
	return result;
}

asmlinkage long our_sys_symlink(const char *path1, const char *path2)
{
	long euid, result;
	long audit, pid;
	struct passwd_entry *pe;
	struct log_path *p;
	result = original_sys_symlink_call(path1, path2);
	if(result >= 0) {
		euid = current_uid();
		audit = get_audit_id();
		pid = current->pid;
		pe = get_passwd_entry(euid);
		p = find_path();
		LOG_LINK(SYSCALL_SYMLINK, pe->username, pid, audit, path1, path2, p->name);
		kfree(p);	
	}
	return result;
}

asmlinkage long our_sys_link(const char* file, const char* newfile) 
{
	long result;
	long uid, gid;
	long audit, pid;
	struct log_path *p; 
	struct passwd_entry *pe = NULL;

	
	if (is_relevant_file(file, &uid, &gid) == 1)
	{
		result = original_sys_link_call(file, newfile);
		if(result >= 0) {
			pid = current->pid;
			uid = current_uid();
			pe = get_passwd_entry(uid);
			audit = get_audit_id();
			p = find_path();
			LOG_LINK(SYSCALL_LINK, pe->username, pid, audit, file, newfile, p->name);
			kfree(p);	
		}	
	}
	else {
		result = original_sys_link_call(file, newfile);
	}
	return result;
}

asmlinkage long our_sys_linkat(int dirfd, const char* file, int newfd, const char* newfile, int flags) 
{
	long result;
	long uid, gid;
	long audit, pid;
	struct passwd_entry *pe = NULL;

	
	if (is_relevant_file(file, &uid, &gid) == 1)
	{
		result = original_sys_linkat_call(dirfd, file, newfd, newfile, flags);
		if(result >= 0) {
			pid = current->pid;
			uid = current_uid();
			audit = get_audit_id();
			pe = get_passwd_entry(uid);
			LOG_LINKAT(SYSCALL_LINKAT, pe->username, pid, audit, file, newfile, dirfd, newfd, flags);
		}	
	}
	else {
		result = original_sys_linkat_call(dirfd, file, newfd, newfile, flags);
	}
	return result;
}

asmlinkage long our_sys_chown(const char *file, uid_t owner, gid_t group) 
{
	long fd = 0;
	long uid, gid;
	long audit, pid;
	struct task_struct *task = NULL;
	struct passwd_entry *pe = NULL;

	
	if (is_relevant_file(file, &uid, &gid) == 1)
	{
		fd = original_sys_chown_call(file, owner, group);
		if(fd >= 0) {
			pid = current->pid;
			uid = current_uid();
			audit = get_audit_id();
			pe = get_passwd_entry(uid);
			task = find_task_by_vpid(pid);
			LOG_CHOWN(SYSCALL_CHOWN, pe->username, pid, audit, task->comm, file, owner, group);
		}	
	}
	else {
		fd = original_sys_chown_call(file, owner, group);
	}
	return fd;
}

asmlinkage long our_sys_fchown(int filefd, uid_t owner, gid_t group) 
{
	long fd = 0;
	long uid;
	long audit, pid;
	struct task_struct *task = NULL;
	struct passwd_entry *pe = NULL;
	
	fd = original_sys_fchown_call(filefd, owner, group);
	if(fd >= 0) {
		pid = current->pid;
		uid = current_uid();
		audit = get_audit_id();
		pe = get_passwd_entry(uid);
		task = find_task_by_vpid(pid);
		LOG_FCHOWN(SYSCALL_FCHOWN, pe->username, pid, audit, task->comm, filefd, owner, group);
	}	
	return fd;
}

asmlinkage long our_sys_lchown(const char *file, uid_t owner, gid_t group) 
{
	long fd = 0;
	long uid, gid;
	long audit, pid;
	struct task_struct *task = NULL;
	struct passwd_entry *pe = NULL;
	
	if (is_relevant_file(file, &uid, &gid) == 1)
	{
		fd = original_sys_lchown_call(file, owner, group);
		if(fd >= 0) {
			pid = current->pid;
			uid = current_uid();
			audit = get_audit_id();
			pe = get_passwd_entry(uid);
			task = find_task_by_vpid(pid);

			LOG_CHOWN(SYSCALL_LCHOWN, pe->username, pid, audit, task->comm, file, owner, group);
		}	
	}
	else {
		fd = original_sys_lchown_call(file, owner, group);
	}
	return fd;
}

asmlinkage long our_sys_fchownat(int dirfd, const char *file, uid_t owner, gid_t group, int flags) 
{
	long fd = 0;
	long uid, gid;
	long audit, pid;
	struct task_struct *task = NULL;
	struct passwd_entry *pe = NULL;

	if (is_relevant_file(file, &uid, &gid) == 1)
	{
		fd = original_sys_fchownat_call(dirfd, file, owner, group, flags);
		if(fd >= 0) {
			pid = current->pid;
			uid = current_uid();
			pe = get_passwd_entry(uid);
			audit = get_audit_id();
			task = find_task_by_vpid(pid);
			LOG_FCHOWNAT(SYSCALL_FCHOWNAT, pe->username, pid, audit, task->comm, file, dirfd, owner, group, flags);
		}	
	}
	else {
		fd = original_sys_fchownat_call(dirfd, file, owner, group, flags);
	}
	return fd;
}

asmlinkage long our_sys_chmod(const char *file, mode_t mode) 
{
	long fd = 0;
	long uid, gid;
	long audit, pid;
	struct task_struct *task = NULL;
	struct passwd_entry *pe = NULL;

	if (is_relevant_file(file, &uid, &gid) == 1)
	{
		fd = original_sys_chmod_call(file, mode);
		if(fd >= 0) {
			pid = current->pid;
			uid = current_uid();
			pe = get_passwd_entry(uid);
			task = find_task_by_vpid(pid);
			audit = get_audit_id();
			
			LOG_CHMOD(SYSCALL_CHMOD, pe->username, pid, audit, task->comm, file, mode);
		}	
	}
	else {
		fd = original_sys_chmod_call(file, mode);
	}
	return fd;
}

asmlinkage long our_sys_fchmod(int filefd, mode_t mode) 
{
	long fd = 0;
	long uid;
	long audit, pid;
	struct task_struct *task = NULL;
	struct passwd_entry *pe = NULL;

	fd = original_sys_fchmod_call(filefd, mode);
	if(fd >= 0) {
		pid = current->pid;
		uid = current_uid();
		pe = get_passwd_entry(uid);
		task = find_task_by_vpid(pid);
		audit = get_audit_id();

		LOG_FCHMOD(SYSCALL_FCHMOD, pe->username, pid, audit, task->comm, filefd, mode);
	}	
	return fd;
}

asmlinkage long our_sys_fchmodat(int dirfd, const char *file, mode_t mode, int flags) 
{
	long fd = 0;
	long uid, gid;
	long audit, pid;
	struct task_struct *task = NULL;
	struct passwd_entry *pe = NULL;

	
	if (is_relevant_file(file, &uid, &gid) == 1)
	{
		fd = original_sys_fchmodat_call(dirfd, file, mode, flags);
		if(fd >= 0) {
			pid = current->pid;
			uid = current_uid();
			pe = get_passwd_entry(uid);
			task = find_task_by_vpid(pid);
			audit = get_audit_id();

			LOG_FCHMODAT(SYSCALL_FCHMODAT, pe->username, pid, audit, task->comm, file, dirfd, mode,flags);
		}	
	}
	else {
		fd = original_sys_fchmodat_call(dirfd, file, mode, flags);
	}
	return fd;
}

asmlinkage long our_sys_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
	long result;
	long audit, pid;
	struct passwd_entry *pe = NULL;
	result = original_sys_sendfile_call(out_fd, in_fd, offset, count);
	if(result >= 0) {
		pid = current->pid;
		audit = get_audit_id();
		pe = get_passwd_entry(current_uid());
			
		LOG_SENDFILE(SYSCALL_SENDFILE, pe->username, pid, audit, out_fd, in_fd, *offset, count);	
	}
	return result;
} 

asmlinkage long our_sys_pipe(int pipefd[2])
{
	long result;
	long audit, pid, paudit;
	struct passwd_entry *pe = NULL;
	struct task_struct *ts = NULL;
	
	result = original_sys_pipe_call(pipefd);
	if(result < 0) return result;

	pid = current->pid;
	audit = get_audit_id();
	pe = get_passwd_entry(current_uid());

	ts = find_task_by_vpid(audit);
	if(ts != NULL && ts->real_parent != NULL) {
		paudit = ts->real_parent->pid;
	}
	else {
		paudit = -1;
	}
	LOG_PIPE(SYSCALL_PIPE, pe->username, pid, audit, paudit, pipefd[0], pipefd[1], 0);
	
	
	return result;
}

asmlinkage long our_sys_pipe2(int pipefd[2], int flags)
{
	long result;
	long audit, pid, paudit;
	struct passwd_entry *pe = NULL;
	struct task_struct *ts = NULL;
	
	result = original_sys_pipe2_call(pipefd, flags);
	if(result < 0) return result;

	pid = current->pid;
	audit = get_audit_id();
	pe = get_passwd_entry(current_uid());

	ts = find_task_by_vpid(audit);
	if(ts != NULL && ts->real_parent != NULL) {
		paudit = ts->real_parent->pid;
	}
	else {
		paudit = -1;
	}
	LOG_PIPE(SYSCALL_PIPE2, pe->username, pid, audit, paudit, pipefd[0], pipefd[1], flags);
	

	return result;
}

asmlinkage long our_sys_dup(unsigned int filde)
{
	long result;
	long uid, audit;
	long pid;
	struct passwd_entry *pe = NULL;
	
	result = original_sys_dup_call(filde);
	if(result < 0) return result;

	uid = current_uid();
	audit = get_audit_id();
	pid = current->pid;
	pe = get_passwd_entry(uid);
	LOG_DUP2(SYSCALL_DUP, pe->username, pid, 0, audit, 0, filde, result);
	return result;
}


/* Not Implemented fully yet */

asmlinkage long our_sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
	return original_sys_writev_call(fd, vec, vlen);
}

asmlinkage long our_sys_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos)
{
	return original_sys_pwrite64_call(fd, buf, count, pos);
}
