struct log_path
{
	char *mem;
	char *name;
};

struct process_ids
{
	long uid;
	long pid;
	long ppid;
	long audit;
	long paudit;
};

struct log_path *find_path(void);
inline long get_audit_id(void);
void disable_page_protection(long unsigned int value);
void enable_page_protection(long unsigned int value);
long atoi2(const char *inputstring);

