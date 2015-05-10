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
 DISCLAIMED. IN NO EVENT SHALL CROW BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#define PROGGER_ID "Progger:"

/* Sample rsyslog config file:
 *
 *  ...
 *  if $msg startswith 'Progger' then /var/log/progger.log
 *  if $msg startswith 'Progger' then ~
 *  ...
 *  
 * For more information on rsyslog, see http://wiki.rsyslog.com/index.php/Main_Page
 */

/* Log Formats:
 *  Formats can be easily changed below by rearranging or removing values from the prink statement,
 *  however for additional values, the macros must be updated in the source code.
 */
#define LOG_OPEN(type,user,pid,ppid,audit,paudit,pname,filename,path,flags,mode,fd) printk(KERN_INFO "%s%d,%s,%lu,%lu,%lu,%lu,%s,%s,%s,%u,%u,%lu\n",PROGGER_ID,type,user,pid,ppid,audit,paudit,pname,filename,path,flags,mode,fd)
#define LOG_CLOSE(type,user,pid,ppid,audit,paudit,fd) printk(KERN_INFO "%s%d,%s,%lu,%lu,%lu,%lu,%u\n",PROGGER_ID,type,user,pid,ppid,audit,paudit,fd)
#define LOG_S_CLOSE(type,user,pid,ppid,audit,paudit,fd) printk(KERN_INFO "%s%d,%s,%lu,%lu,%lu,%lu,%us\n",PROGGER_ID,type,user,pid,ppid,audit,paudit,fd)
#define LOG_RENAME(type,user,pid,ppid,audit,paudit,pname,oldfile,newfile,path) printk(KERN_INFO "%s%d,%s,%lu,%lu,%lu,%lu,%s,%s,%s,%s\n",PROGGER_ID,type,user,pid,ppid,audit,paudit,pname,oldfile,newfile,path)
#define LOG_UNLINK(type,user,pid,ppid,audit,paudit,pname,filename,path) printk(KERN_INFO "%s%d,%s,%lu,%lu,%lu,%lu,%s,%s,%s\n",PROGGER_ID,type,user,pid,ppid,audit,paudit,pname,filename,path)
#define LOG_UNLINKAT(type,user,pid,ppid,audit,paudit,pname,filename,path,dirfd,flags) printk(KERN_INFO "%s%d,%s,%lu,%lu,%lu,%lu,%s,%s,%s,%u,%u\n",PROGGER_ID,type,user,pid,ppid,audit,paudit,pname,filename,path,dirfd,flags)
#define LOG_DUP2(type,user,pid,ppid,audit,paudit,oldfd,newfd)printk(KERN_INFO"%s%d,%s,%lu,%lu,%lu,%lu,%u,%u\n",PROGGER_ID,type,user,pid,ppid,audit,paudit,oldfd,newfd)
#define LOG_RDWR(type,user,pid,ppid,audit,paudit,fd,pos,data)printk(KERN_INFO"%s%d,%s,%lu,%lu,%lu,%lu,%u,%lu,%s\n",PROGGER_ID,type,user,pid,ppid,audit,paudit,fd,pos,data)
#define LOG_S_RDWR(type,user,pid,ppid,audit,paudit,fd,pos,data) printk(KERN_INFO"%s%d,%s,%lu,%lu,%lu,%lu,%us,%lu,%s\n",PROGGER_ID,type,user,pid,ppid,audit,paudit,fd,pos,data)
#define LOG_MKDIR(type,user,pid,audit,name,path,mode) printk(KERN_INFO"%s%d,%s,%lu,%lu,%s,%s,%u\n",PROGGER_ID,type,user,pid,audit,name,path,mode)
#define LOG_RMDIR(type,user,pid,audit,name,path) printk(KERN_INFO"%s%d,%s,%lu,%lu,%s,%s\n",PROGGER_ID,type,user,pid,audit,name,path)
#define LOG_LINK(type,user,pid,audit,path1,path2,wd) printk(KERN_INFO"%s%d,%s,%lu,%lu,%s,%s,%s\n",PROGGER_ID,type,user,pid,audit,path1,path2,wd)
#define LOG_LINKAT(type,user,pid,audit,path1,path2,dir1,dir2,flags) printk(KERN_INFO"%s%d,%s,%lu,%lu,%s,%s,%d,%d,%d\n",PROGGER_ID,type,user,pid,audit,path1,path2,dir1,dir2,flags)
#define LOG_CHOWN(type,user,pid,audit,pname,file,owner,group) printk(KERN_INFO"%s%d,%s,%lu,%lu,%s,%s,%u,%u\n",PROGGER_ID,type,user,pid,audit,pname,file,owner,group)
#define LOG_FCHOWN(type,user,pid,audit,pname,file,owner,group) printk(KERN_INFO"%s%d,%s,%lu,%lu,%s,%d,%u,%u\n",PROGGER_ID,type,user,pid,audit,pname,file,owner,group)
#define LOG_FCHOWNAT(type,user,pid,audit,pname,file,dirfd,owner,group,flags) printk(KERN_INFO"%s%d,%s,%lu,%lu,%s,%s,%d,%u,%u,%d\n",PROGGER_ID,type,user,pid,audit,pname,file,dirfd,owner,group,flags)
#define LOG_CHMOD(type,user,pid,audit,pname,file,mode) printk(KERN_INFO"%s%d,%s,%lu,%lu,%s,%s,%u\n",PROGGER_ID,type,user,pid,audit,pname,file,mode)
#define LOG_FCHMOD(type,user,pid,audit,pname,file,mode) printk(KERN_INFO"%s%d,%s,%lu,%lu,%s,%u,%u\n",PROGGER_ID,type,user,pid,audit,pname,file,mode)
#define LOG_FCHMODAT(type,user,pid,audit,pname,file,dirfd,mode,flags) printk(KERN_INFO"%s%d,%s,%lu,%lu,%s,%s,%u,%u,%u\n",PROGGER_ID,type,user,pid,audit,pname,file,dirfd,mode,flags)
#define LOG_SENDFILE(type,user,pid,audit,outfd,infd,offset,count) printk(KERN_INFO"%s%d,%s,%lu,%lu,%u,%u,%lu,%lu\n",PROGGER_ID,type,user,pid,audit,outfd,infd,offset,count)
#define LOG_PIPE(type,user,pid,audit,paudit,fd1,fd2,flags) printk(KERN_INFO"%s%d,%s,%lu,%lu,%lu,%u,%u,%u\n",PROGGER_ID,type,user,pid,audit,paudit,fd1,fd2,flags)


#define LOG_S_CONNECT(type,user,pid,audit,sockfd,ip,port)printk(KERN_INFO"%s%d,%s,%lu,%lu,%us,%d,%d\n",PROGGER_ID,type,user,pid,audit,sockfd,ip,port)
#define LOG_S_SOCKET(type,user,pid,audit,pname,sockfd,stype,sprotocol,sfamily) printk(KERN_INFO"%s%d,%s,%lu,%lu,%s,%lus,%d,%d,%d\n",PROGGER_ID,type,user,pid,audit,pname,sockfd,stype,sprotocol,sfamily)
#define LOG_S_SENDRECV(type,user,pid,audit,sockfd,flags,len,dest,data) printk(KERN_INFO"%s%d,%s,%lu,%lu,%us,%u,%lu,%d,%s\n",PROGGER_ID,type,user,pid,audit,sockfd,flags,len,dest,data)
#define LOG_S_MSG(type,user,pid,audit,sockfd,flags,len,data) printk(KERN_INFO"%s%d,%s,%lu,%lu,%us,%u,%u,%s\n",PROGGER_ID,type,user,pid,audit,sockfd,flags,len,data)
