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

#define PASSWDFILE "/etc/passwd"
#define MAXLEN 1023
#define IDX_USERNAME 0
#define IDX_PASSWORD 1
#define IDX_UID 2
#define IDX_GID 3
#define IDX_UID_INFO 4
#define IDX_HOME_DIR 5
#define IDX_COMMAND_SHELL 6
#define CHUNKSIZE 1024
#define UIDLEN 32768

/* Types */
struct passwd_entry
{
	char username[MAXLEN+1];
	char username_root[MAXLEN+2];
	char password[MAXLEN+1];
	char uid[MAXLEN+1];
	char gid[MAXLEN+1];
	char uid_info[MAXLEN+1];
	char home_dir[MAXLEN+1];
	char command_shell[MAXLEN+1];
};

/* Prototypes */
struct passwd_entry* get_passwd_entry(long uid); 
void cleanup_passwd_entries(void);
