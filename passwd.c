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

#include "passwd.h"

static struct passwd_entry **passwd_entries = NULL;

static int read_textfile(const char *filename, char **outputbuf, unsigned long *outputbufsize)
{
   struct file *srcf = NULL;
   char buf[CHUNKSIZE];
   mm_segment_t old_fs;

   char *workbuf = NULL;
   int workcount = 0;
   unsigned long workpos = 0;

   int flag = 0;
   int retval;
   int a = 0;

#ifdef DEBUG2
   unsigned long bytesread = 0;
#endif


   old_fs = get_fs();
   set_fs(KERNEL_DS);

   srcf = filp_open(filename, O_RDONLY, 0);

   if (IS_ERR(srcf) )
   {
      printk("kerneltrust: Error opening text file %s\n", filename);
      srcf = NULL;
      flag = -1;
   }


   if (srcf)
   {
      while (vfs_read(srcf, buf, CHUNKSIZE, &srcf->f_pos) > 0)
      {

         #ifdef DEBUG2

            printk("*** Begin workbuf %lu ***\n", srcf->f_pos);

            for (a=0; a < CHUNKSIZE && bytesread < srcf->f_pos && buf[a] != 0; a++, bytesread++)
            {
               printk("%c", buf[a] );
            }

            printk("*** End workbuf ***\n");

         #endif


         workcount++;
         workbuf = krealloc(workbuf, workcount*CHUNKSIZE*sizeof(char), GFP_KERNEL); 

         if (workbuf == NULL)
         {
            printk(KERN_ALERT "kerneltrust: Error krealloc for workbuf!\n");
            workpos = -1;
            flag = -1;
            break;
         }


         /* append buf to workbuf */

         for (a=0; a < CHUNKSIZE && workpos < srcf->f_pos && workbuf && buf[a] != 0; a++, workpos++)
         {
            workbuf[workpos] = buf[a];
         }

      }


      #ifdef DEBUG2

         for (a=0; a < workpos && workbuf && workbuf[a] != 0; a++)
         {
            printk("%c", workbuf[a] );
         }

      #endif

   }


   if (srcf)
   {
      retval = filp_close(srcf, NULL);

      if (retval)
      {
         printk("kerneltrust: Error %d closing text file %s\n", -retval, filename);
      }
   }


   *outputbuf = workbuf;
   *outputbufsize = workpos+1;

   set_fs(old_fs);

   return flag;
}

static int parse_passwdfile(const char *inputstring_param, const unsigned long inputstring_len_param) {
	char *buff = kmalloc(sizeof(char) * (MAXLEN + 2), GFP_KERNEL);	
	const char *passwd = inputstring_param;
	int i, e, pei;
	struct passwd_entry *entry;

#ifdef DEBUG
	printk(KERN_ALERT "Looking at the passwd file!\n");
#endif
	if(passwd_entries == NULL) {
		passwd_entries = kmalloc(UIDLEN * sizeof(struct passwd_entry *), GFP_KERNEL);
		for(i = 0; i < UIDLEN; i++) passwd_entries[i] = NULL;
	}

	i = 0;
	e = 0;
	buff[i] = '\0';
	entry = kmalloc(sizeof(struct passwd_entry), GFP_KERNEL);
	while(1) {
		if(*passwd == '\0' || i == MAXLEN + 2) break;
		if(*passwd == '\n' || *passwd == ':') {
			buff[i] = '\0';
			if(e == IDX_USERNAME) {	
				memcpy(entry->username, buff, strlen(buff) + 1);
				buff[i] = '*';
				buff[i+1] = '\0';
				memcpy(entry->username_root, buff, strlen(buff) + 1);
			}
			else if(e == IDX_PASSWORD) memcpy(entry->password, buff, strlen(buff) + 1);
			else if(e == IDX_UID)	   memcpy(entry->uid, buff, strlen(buff) + 1);
			else if(e == IDX_GID)      memcpy(entry->gid, buff, strlen(buff) + 1);
			else if(e == IDX_UID_INFO) memcpy(entry->uid_info, buff, strlen(buff) + 1);
			else if(e == IDX_HOME_DIR) memcpy(entry->home_dir, buff, strlen(buff) + 1);
			else if(e == IDX_COMMAND_SHELL)	{
				memcpy(entry->command_shell, buff, strlen(buff) + 1);
				pei = atoi2(entry->uid);
				if(passwd_entries[pei] != NULL) kfree(passwd_entries[pei]);
				passwd_entries[pei] = entry;
				e = -1;
#ifdef DEBUG
				printk(KERN_ALERT "UID Found: %d\n", pei);
#endif
				entry = kmalloc(sizeof(struct passwd_entry), GFP_KERNEL);
			}
			e++;
			i = 0;
			buff[i] = '\0';
		}
		else {
			buff[i++] = *passwd;
		}
		passwd++;
	}
	kfree(buff);
	return 0;
}

struct passwd_entry* get_passwd_entry(long uid)
{
	char *tempbuf = NULL;
	unsigned long tempbufsize = 0;
	if(passwd_entries == NULL || passwd_entries[uid] == NULL) {
		read_textfile(PASSWDFILE, &tempbuf, &tempbufsize);
		parse_passwdfile(tempbuf, tempbufsize);
	}
	return passwd_entries[uid];
}

void cleanup_passwd_entries()
{
	int i;
	for(i = 0; i < UIDLEN; i++) {
		if(passwd_entries[i] != NULL) kfree(passwd_entries[i]);	
	}
	kfree(passwd_entries);
}
