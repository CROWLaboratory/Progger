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

#define SYSCALL_OPEN		0
#define SYSCALL_UNLINK		1
#define SYSCALL_WRITE		2
#define SYSCALL_CREAT		3
#define SYSCALL_MOVE		4
#define SYSCALL_CLOSE		5
#define SYSCALL_READ		6
#define SYSCALL_S_CONNECT 	7
#define SYSCALL_S_SENDTO	8
#define SYSCALL_UNLINKAT	9
#define SYSCALL_MKDIR		10
#define SYSCALL_RMDIR		11
#define SYSCALL_SYMLINK		12
#define SYSCALL_LINK		13
#define SYSCALL_LINKAT		14
#define SYSCALL_CHOWN		15
#define SYSCALL_FCHOWN		16
#define SYSCALL_LCHOWN		17
#define SYSCALL_FCHOWNAT	18
#define SYSCALL_CHMOD		19
#define SYSCALL_FCHMOD		20
#define SYSCALL_FCHMODAT	21
#define SYSCALL_S_SENDMSG	22
#define SYSCALL_S_ACCEPT	23
#define SYSCALL_S_SOCKET	24
#define SYSCALL_SENDFILE	25
#define SYSCALL_S_RECVFROM	26
#define SYSCALL_S_RECVMSG	27
#define SYSCALL_DUP2		28
#define SYSCALL_PIPE		29
#define SYSCALL_PIPE2		30
#define SYSCALL_DUP		31
#define SYSCALL_PWRITE		32
