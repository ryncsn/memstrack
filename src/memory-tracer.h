extern int memtrac_debug;
extern int memtrac_human;
extern int memtrac_perf;
extern int memtrac_slab;
extern int memtrac_page;
extern int memtrac_ftrace;
extern int memtrac_json;
extern int memtrac_print;
extern unsigned int page_size;

#define LOG_LVL_DEBUG 0
#define LOG_LVL_INFO 1
#define LOG_LVL_WARN 2
#define LOG_LVL_ERROR 3

extern int memtrac_log (int level, const char *__restrict __fmt, ...);

#define log_debug(...) memtrac_log(LOG_LVL_DEBUG, __VA_ARGS__)
#define log_info(...) memtrac_log(LOG_LVL_INFO, __VA_ARGS__)
#define log_warn(...) memtrac_log(LOG_LVL_WARN, __VA_ARGS__)
#define log_error(...) memtrac_log(LOG_LVL_ERROR, __VA_ARGS__)
