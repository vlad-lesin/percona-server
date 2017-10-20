/* Copyright (c) 2015-2016 Percona LLC and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; version 2 of
   the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

#ifndef AUDIT_LOG_H_INCLUDED
#define AUDIT_LOG_H_INCLUDED

#include <mysql/plugin.h>
#include <m_ctype.h>

extern PSI_memory_key key_memory_audit_log_logger_handle;
extern PSI_memory_key key_memory_audit_log_handler;
extern PSI_memory_key key_memory_audit_log_buffer;
extern PSI_memory_key key_memory_audit_log_accounts;
extern PSI_memory_key key_memory_audit_log_databases;
extern PSI_memory_key key_memory_audit_log_commands;
extern MYSQL_PLUGIN plugin_ptr;
extern ulong audit_log_format;

typedef struct
{
  /* number of included databases */
  int databases_included;
  /* number of excluded databases */
  int databases_excluded;
  /* number of accessed databases */
  int databases_accessed;
  /* query */
  const char *query;
} query_stack_frame;

typedef struct
{
  size_t size;
  size_t top;
  query_stack_frame *frames;
} query_stack;

/*
 Struct to store various THD specific data
 */
typedef struct
{
  /* size of allocated large buffer for record formatting */
  size_t record_buffer_size;
  /* large buffer for record formatting */
  char *record_buffer;
  /* skip session logging */
  my_bool skip_session;
  /* skip logging for the next query */
  my_bool skip_query;
  /* default database */
  char db[NAME_LEN + 1];
  /* default database candidate */
  char init_db_query[NAME_LEN + 1];
  /* call stack */
  query_stack stack;
} audit_log_thd_local;

#define MAX_RECORD_ID_SIZE  50
#define MAX_TIMESTAMP_SIZE  25

#ifdef __cplusplus
extern "C" {
#endif

extern MYSQL_PLUGIN_IMPORT CHARSET_INFO *system_charset_info;

/*
 Return pointer to THD specific data.
 */
audit_log_thd_local *get_thd_local(MYSQL_THD thd);

/*
 Allocate and return buffer of given size.
 */
char *get_record_buffer(MYSQL_THD thd, size_t size);
void audit_log_write(const char *buf, size_t len);
char *escape_string(const char *in, size_t inlen,
                    char *out, size_t outlen,
                    char **endptr, size_t *full_outlen);
char *make_record_id(char *buf, size_t buf_len);
char *make_timestamp(char *buf, size_t buf_len, time_t t);

#ifdef __cplusplus
}
#endif

#define AUDIT_LOG_PSI_CATEGORY "audit_log"

#endif /* AUDIT_LOG_H_INCLUDED */
