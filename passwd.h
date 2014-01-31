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
