#ifndef LOCK_WAITS_TIMEOUT_H_INCLUDED
#define LOCK_WAITS_TIMEOUT_H_INCLUDED

#ifdef __cplusplus
extern "C"
#endif
int process_locks(MYSQL_THD thd,
                  mysql_event_class_t event_class,
                  const void *event);

#endif
