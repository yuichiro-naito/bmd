#ifndef _LOG_H_
#define _LOG_H_
#include <syslog.h>

#define LOG_OPEN() openlog("bhyved", LOG_PID, LOG_DAEMON)
#define LOG_OPEN_PERROR() openlog("bhyved", LOG_PID | LOG_PERROR, LOG_DAEMON)
#define LOG_CLOSE() closelog()

#define ERR(msg, ...) syslog(LOG_ERR, msg, __VA_ARGS__)
#define WARN(msg, ...) syslog(LOG_WARNING, msg, __VA_ARGS__)
#define INFO(msg, ...) syslog(LOG_INFO, msg, __VA_ARGS__)
#define DEBUG(msg, ...) syslog(LOG_DEBUG, msg, __VA_ARGS__)

#endif
