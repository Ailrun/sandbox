#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <utility>
#include <vector>

extern "C" {
#include <sys/resource.h>
}

extern std::string conf_program;
extern std::vector<std::string> conf_arg;
extern bool conf_closefds;
extern bool conf_clearenv;
extern std::vector<std::pair<std::string, std::string>> conf_setenv;
extern std::vector<std::string> conf_unsetenv;
extern std::vector<std::string> conf_see;
extern std::vector<std::string> conf_write;
extern int conf_maxthreads;
extern bool conf_chdir;
extern std::string conf_chdirto;
extern std::vector<std::pair<int, rlim_t>> conf_rlimit;
extern std::vector<std::string> conf_http;
extern std::string conf_downloadpat;
extern std::string conf_sockdir;
extern bool conf_wakeup;
extern int conf_timelimit;
extern bool conf_report;

void read_conf(std::string);

#endif
