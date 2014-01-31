asmlinkage long our_sys_socket(int socket_family, int socket_type, int protocol)
{
	long uid, pid, audit;
	long result = 0;
	struct passwd_entry *pe = NULL;
	struct task_struct *task = NULL;
	result = original_sys_socket_call(socket_family, socket_type, protocol);
	if(result >= 0) {
		uid = current_uid();
		audit = get_audit_id();
		pid = current->pid;
		task = find_task_by_vpid(pid);
		pe = get_passwd_entry(uid);
		task = find_task_by_vpid(pid);
		LOG_S_SOCKET(SYSCALL_S_SOCKET, pe->username, pid, audit, task->comm, result, socket_type, protocol, socket_family);
	}

	return result;
}

asmlinkage long our_sys_connect(int sockfd, struct sockaddr __user *addr, int addrlen)
{
	long uid, pid, audit;
	long result;
	struct passwd_entry *pe;
	struct sockaddr_in  *ipv4;
	unsigned int ipv4_addr;
	//struct sockaddr_in6 *ipv6;
	uid = current_uid();
	audit = get_audit_id();
	pid = current->pid;
	pe = get_passwd_entry(uid);

	result = original_sys_connect_call(sockfd, addr, addrlen);
	if(result < 0) return result;

	if(addr->sa_family == AF_INET) {
		ipv4 = (struct sockaddr_in *) addr;
		ipv4_addr = (unsigned int)(ipv4->sin_addr.s_addr);
		LOG_S_CONNECT(SYSCALL_S_CONNECT, pe->username, pid, audit, sockfd, ipv4_addr, ipv4->sin_port);
	}
	else if(addr->sa_family == AF_INET6){
		// TODO: Suport IPv6
	}
	return result; 
}

asmlinkage long our_sys_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, int addrlen)
{
	struct sockaddr_in  *ipv4;
	//struct sockaddr_in6 *ipv6;
	char *hexdata, *data;
	long uid, pid, audit;
	long result;
	struct passwd_entry *pe;
	unsigned int tmp;	
	int i;
	unsigned int ipv4_addr;

	result = original_sys_sendto_call(sockfd, buf, len, flags, dest_addr, addrlen);
	if(result < 0) return result;

	uid = current_uid();
	audit = get_audit_id();
	pid = current->pid;
	pe = get_passwd_entry(uid);

	// Convert Data to Hex
	hexdata = kmalloc(sizeof(char) * (len * 2 + 1), GFP_KERNEL);
	data = (char *) buf;
	for(i = 0; i < len; i++) {
		tmp = (int)data[i];
		tmp = tmp & 255;
		sprintf(hexdata + (i * 2), "%02X", tmp);
	}
	hexdata[len * 2] = '\0';
	

	if(dest_addr != NULL) {
		if(dest_addr->sa_family == AF_INET) {
			ipv4 = (struct sockaddr_in *) dest_addr;
			ipv4_addr = (unsigned int)(ipv4->sin_addr.s_addr);
			LOG_S_SENDRECV(SYSCALL_S_SENDTO, pe->username, pid, audit, sockfd, flags, len, ipv4_addr, hexdata);
		}
		else if(dest_addr->sa_family == AF_INET6) {
			// TODO: Suport IPv6
		}
	}
	else {
		LOG_S_SENDRECV(SYSCALL_S_SENDTO, pe->username, pid, audit, sockfd, flags, len, 0, hexdata);
	}
	kfree(hexdata);
	return result;
}

asmlinkage long our_sys_sendmsg(int sockfd, const struct msghdr *msg, int flags) 
{
	struct passwd_entry *pe;
	char *hexdata, *data;
	unsigned int tmp, len;	
	int i;
	long result;
	long uid, pid, audit;

	result = original_sys_sendmsg_call(sockfd, msg, flags);
	if(result < 0) return result;

	uid = current_uid();
	audit = get_audit_id();
	pid = current->pid;
	pe = get_passwd_entry(uid);

	// Convert Data to Hex
	len = (unsigned int) msg->msg_iovlen;
	hexdata = kmalloc(sizeof(char) * (len * 2 + 1), GFP_KERNEL);
	data = (char *) msg->msg_iov;
	for(i = 0; i < len; i++) {
		tmp = (int)data[i];
		tmp = tmp & 255;
		sprintf(hexdata + (i * 2), "%02X", tmp);
	}
	hexdata[len * 2] = '\0';

	LOG_S_MSG(SYSCALL_S_SENDMSG, pe->username, pid, audit, sockfd, flags, len, hexdata);
	kfree(hexdata);
	return result;
}

asmlinkage long our_sys_accept(int sockfd, struct sockaddr __user *addr, int *addrlen)
{
	struct sockaddr_in  *ipv4;
	//struct sockaddr_in6 *ipv6;
	long result;
	long uid, pid, audit;
	struct passwd_entry *pe;
	unsigned int ipv4_addr;
	
	result =  original_sys_accept_call(sockfd, addr, addrlen);
	if(result < 0)	return result;

	uid = current_uid();
	audit = get_audit_id();
	pid = current->pid;
	pe = get_passwd_entry(uid);

	if(addr->sa_family == AF_INET) {
		ipv4 = (struct sockaddr_in *) addr;
		ipv4_addr = (unsigned int)(ipv4->sin_addr.s_addr);
		LOG_S_CONNECT(SYSCALL_S_ACCEPT,pe->username,pid,audit, sockfd, ipv4_addr, ipv4->sin_port);
	}
	else if(addr->sa_family == AF_INET6){
		// TODO: Suport IPv6
	}
	return result;
}

asmlinkage long our_sys_recvfrom(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *src_addr, int addrlen)
{
	struct sockaddr_in  *ipv4;
	//struct sockaddr_in6 *ipv6;
	char *hexdata, *data;
	long uid, pid, audit;
	long result;
	struct passwd_entry *pe;
	unsigned int tmp;	
	int i;
	unsigned int ipv4_addr;


	result = original_sys_recvfrom_call(sockfd, buf, len, flags, src_addr, addrlen);
	if(result < 0) return result;

	uid = current_uid();
	audit = get_audit_id();
	pid = current->pid;
	pe = get_passwd_entry(uid);

	// Convert Data to Hex
	hexdata = kmalloc(sizeof(char) * (len * 2 + 1), GFP_KERNEL);
	data = (char *) buf;
	for(i = 0; i < len; i++) {
		tmp = (int)data[i];
		tmp = tmp & 255;
		sprintf(hexdata + (i * 2), "%02X", tmp);
	}
	hexdata[len * 2] = '\0';
	
	if(src_addr != NULL) {
		if(src_addr->sa_family == AF_INET) {
			ipv4 = (struct sockaddr_in *) src_addr;
			ipv4_addr = (unsigned int)(ipv4->sin_addr.s_addr);
			LOG_S_SENDRECV(SYSCALL_S_RECVFROM, pe->username, pid, audit, sockfd, flags, len, ipv4_addr, hexdata);
		}
		else if(src_addr->sa_family == AF_INET6) {
			// TODO: Suport IPv6
		}
	}
	else {
		LOG_S_SENDRECV(SYSCALL_S_RECVFROM, pe->username, pid, audit, sockfd, flags, len, 0, hexdata);
	}
	kfree(hexdata);
	return result; 
}

asmlinkage long our_sys_recvmsg(int sockfd, const struct msghdr *msg, int flags) 
{
	struct passwd_entry *pe;
	char *hexdata, *data;
	unsigned int tmp, len;	
	int i;
	long result;
	long uid, pid, audit;

	result = original_sys_recvmsg_call(sockfd, msg, flags);
	if(result < 0) return result;

	uid = current_uid();
	audit = get_audit_id();
	pid = current->pid;
	pe = get_passwd_entry(uid);

	// Convert Data to Hex
	len = (unsigned int) msg->msg_iovlen;
	hexdata = kmalloc(sizeof(char) * (len * 2 + 1), GFP_KERNEL);
	data = (char *) msg->msg_iov;
	for(i = 0; i < len; i++) {
		tmp = (int)data[i];
		tmp = tmp & 255;
		sprintf(hexdata + (i * 2), "%02X", tmp);
	}
	hexdata[len * 2] = '\0';

	LOG_S_MSG(SYSCALL_S_RECVMSG, pe->username, pid, audit, sockfd, flags, len, hexdata);
	kfree(hexdata);

	return result;
}


