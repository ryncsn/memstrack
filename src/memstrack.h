extern int m_debug;
extern int m_human;
extern int m_perf;
extern int m_slab;
extern int m_page;
extern int m_ftrace;
extern int m_json;
extern int m_print;
extern int m_throttle;
extern int m_summary;
extern int m_sort_alloc;
extern int m_sort_peak;
extern unsigned int page_size;

#define LOG_LVL_DEBUG 0
#define LOG_LVL_INFO 1
#define LOG_LVL_WARN 2
#define LOG_LVL_ERROR 3

extern int m_log (int level, const char *__restrict __fmt, ...);

#define log_debug(...) m_log(LOG_LVL_DEBUG, __VA_ARGS__)
#define log_info(...) m_log(LOG_LVL_INFO, __VA_ARGS__)
#define log_warn(...) m_log(LOG_LVL_WARN, __VA_ARGS__)
#define log_error(...) m_log(LOG_LVL_ERROR, __VA_ARGS__)
