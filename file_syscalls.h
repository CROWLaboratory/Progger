struct log_entry
{
	int type;
	long fd;
	loff_t offset;
	char *username;
	char *owner;
	char *filename;
	char *data;
	struct timeval time;
};
