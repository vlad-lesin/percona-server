#include <mysql/plugin_audit.h>
#include <mysql/service_security_context.h>
#include <mysql/service_srv_session_info.h>
#include <handler.h>

#include "audit_log.h"
#include "lock_waits_timeout.h"

#include <memory>
#include <string>
#include <utility>
#include <inttypes.h>
#include <time.h>

static void switch_user(MYSQL_SESSION session)
{
  static const char *user_localhost = "localhost";
  static const char *user_local = "127.0.0.1";
  static const char *user_db= "";
  static const char *user_privileged= "root";

  MYSQL_SECURITY_CONTEXT sc;

  thd_get_security_context(srv_session_info_get_thd(session), &sc);
  security_context_lookup(
    sc, user_privileged, user_localhost, user_local, user_db);
}

struct st_send_field_n
{
  char db_name[256];
  char table_name[256];
  char org_table_name[256];
  char col_name[256];
  char org_col_name[256];
  unsigned long length;
  unsigned int charsetnr;
  unsigned int flags;
  unsigned int decimals;
  enum_field_types type;
};

struct st_decimal_n
{
  int    intg, frac, len;
  my_bool sign;
  decimal_digit_t buf[256];
};

struct st_plugin_ctx
{
  const CHARSET_INFO *resultcs;
  uint meta_server_status;
  uint meta_warn_count;
  uint current_col;
  uint num_cols;
  uint num_rows;
  st_send_field_n sql_field[64];
  char sql_str_value[64][64][256];
  size_t sql_str_len[64][64];
  longlong sql_int_value[64][64];
  longlong sql_longlong_value[64][64];
  uint sql_is_unsigned[64][64];
  st_decimal_n sql_decimal_value[64][64];
  double sql_double_value[64][64];
  uint32 sql_double_decimals[64][64];
  MYSQL_TIME sql_date_value[64][64];
  MYSQL_TIME sql_time_value[64][64];
  uint sql_time_decimals[64][64];
  MYSQL_TIME sql_datetime_value[64][64];
  uint sql_datetime_decimals[64][64];

  uint server_status;
  uint warn_count;
  uint affected_rows;
  uint last_insert_id;
  char message[1024];

  uint sql_errno;
  char err_msg[1024];
  char sqlstate[6];
  st_plugin_ctx()
  {
    reset();
  }

  void reset()
  {
    resultcs= NULL;
    server_status= 0;
    current_col= 0;
    warn_count= 0;
    num_cols= 0;
    num_rows= 0;
    memset(&sql_field, 0, 64 * sizeof(st_send_field_n));
    memset(&sql_str_value, 0, 64 * 64 * 256 * sizeof(char));
    memset(&sql_str_len, 0, 64 * 64 * sizeof(size_t));
    memset(&sql_int_value, 0, 64 * 64 * sizeof(longlong));
    memset(&sql_longlong_value, 0, 64 * 64 * sizeof(longlong));
    memset(&sql_is_unsigned, 0, 64 * 64 * sizeof(uint));
    memset(&sql_decimal_value, 0, 64 * 64 * sizeof(st_decimal_n));
    memset(&sql_double_value, 0, 64 * 64 * sizeof(double));
    memset(&sql_double_decimals, 0, 64 * 64 * sizeof(uint32));
    memset(&sql_date_value, 0, 64 * 64 * sizeof(MYSQL_TIME));
    memset(&sql_time_value, 0, 64 * 64 * sizeof(MYSQL_TIME));
    memset(&sql_time_decimals, 0, 64 * 64 * sizeof(uint));
    memset(&sql_datetime_value, 0, 64 * 64 * sizeof(MYSQL_TIME));
    memset(&sql_datetime_decimals, 0, 64 * 64 * sizeof(uint));

    server_status= 0;
    warn_count= 0;
    affected_rows= 0;
    last_insert_id= 0;
    memset(&message, 0, sizeof(message));

    sql_errno= 0;
    memset(&err_msg, 0, sizeof(err_msg));
    memset(&sqlstate, 0, sizeof(sqlstate));
  }
};

static int sql_start_result_metadata(void *ctx, uint num_cols, uint flags,
                                     const CHARSET_INFO *resultcs)
{
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_start_result_metadata");
  DBUG_PRINT("info",("resultcs->number: %d", resultcs->number));
  DBUG_PRINT("info",("resultcs->csname: %s", resultcs->csname));
  DBUG_PRINT("info",("resultcs->name: %s", resultcs->name));
  pctx->num_cols= num_cols;
  pctx->resultcs= resultcs;
  pctx->current_col= 0;
  DBUG_RETURN(false);
}

static int sql_field_metadata(void *ctx, struct st_send_field *field,
                              const CHARSET_INFO *charset)
{
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  st_send_field_n *cfield= &pctx->sql_field[pctx->current_col];
  DBUG_ENTER("sql_field_metadata");
  DBUG_PRINT("info",("field->db_name: %s", field->db_name));
  DBUG_PRINT("info",("field->table_name: %s", field->table_name));
  DBUG_PRINT("info",("field->org_table_name: %s", field->org_table_name));
  DBUG_PRINT("info",("field->col_name: %s", field->col_name));
  DBUG_PRINT("info",("field->org_col_name: %s", field->org_col_name));
  DBUG_PRINT("info",("field->length: %d", (int)field->length));
  DBUG_PRINT("info",("field->charsetnr: %d", (int)field->charsetnr));
  DBUG_PRINT("info",("field->flags: %d", (int)field->flags));
  DBUG_PRINT("info",("field->decimals: %d", (int)field->decimals));
  DBUG_PRINT("info",("field->type: %d", (int)field->type));

  strcpy(cfield->db_name,        (char*)field->db_name);
  strcpy(cfield->table_name,     (char*)field->table_name);
  strcpy(cfield->org_table_name, (char*)field->org_table_name);
  strcpy(cfield->col_name,       (char*)field->col_name);
  strcpy(cfield->org_col_name,   (char*)field->org_col_name);
  cfield->length=    field->length;
  cfield->charsetnr= field->charsetnr;
  cfield->flags=     field->flags;
  cfield->decimals=  field->decimals;
  cfield->type=      field->type;

  pctx->current_col++;
  DBUG_RETURN(false);
}

static int sql_end_result_metadata(void *ctx, uint server_status,
                                   uint warn_count)
{
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_end_result_metadata");
  pctx->meta_server_status= server_status;
  pctx->meta_warn_count= warn_count;
  pctx->num_rows= 0;
  DBUG_RETURN(false);
}

static int sql_start_row(void *ctx)
{
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_start_row");
  pctx->current_col= 0;
  DBUG_RETURN(false);
}

static int sql_end_row(void *ctx)
{
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_end_row");
  pctx->num_rows++;
  DBUG_RETURN(false);
}

static void sql_abort_row(void *ctx)
{
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_abort_row");
  pctx->current_col= 0;
  DBUG_VOID_RETURN;
}

static ulong sql_get_client_capabilities(void *ctx){
  DBUG_ENTER("sql_get_client_capabilities");
  DBUG_RETURN(0);
}

static int sql_get_null(void *ctx)
{
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_get_null");
  uint row= pctx->num_rows;
  uint col= pctx->current_col;
  pctx->current_col++;

  strncpy(pctx->sql_str_value[row][col], "[NULL]", sizeof("[NULL]")-1);
  pctx->sql_str_len[row][col]=  sizeof("[NULL]")-1;

  DBUG_RETURN(false);
}

static int sql_get_integer(void * ctx, longlong value)
{
  char buffer[1024];
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_get_integer");
  uint row= pctx->num_rows;
  uint col= pctx->current_col;
  pctx->current_col++;

  size_t len= my_snprintf(buffer, sizeof(buffer), "%d", value);

  strncpy(pctx->sql_str_value[row][col], buffer, len);
  pctx->sql_str_len[row][col]= len;
  pctx->sql_int_value[row][col]= value;

  DBUG_RETURN(false);
}

static int sql_get_longlong(void * ctx, longlong value, uint is_unsigned)
{
  char buffer[1024];
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_get_longlong");
  uint row= pctx->num_rows;
  uint col= pctx->current_col;
  pctx->current_col++;

  size_t len= my_snprintf(buffer, sizeof(buffer),
                          is_unsigned? "%llu":"%lld", value);

  strncpy(pctx->sql_str_value[row][col], buffer, len);
  pctx->sql_str_len[row][col]= len;
  pctx->sql_longlong_value[row][col]= value;
  pctx->sql_is_unsigned[row][col]= is_unsigned;

  DBUG_RETURN(false);
}

static int sql_get_decimal(void * ctx, const decimal_t * value)
{
  char buffer[1024];
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_get_decimal");
  uint row= pctx->num_rows;
  uint col= pctx->current_col;
  pctx->current_col++;

  size_t len= my_snprintf(buffer, sizeof(buffer),
                          "%s%d.%d(%d)[%s]",
                          value->sign? "+":"-",
                          value->intg, value->frac, value->len,
                          value->buf);

  strncpy(pctx->sql_str_value[row][col], buffer, len);

  pctx->sql_str_len[row][col]= len;
  pctx->sql_decimal_value[row][col].intg= value->intg;
  pctx->sql_decimal_value[row][col].frac= value->frac;
  pctx->sql_decimal_value[row][col].len = value->len ;
  pctx->sql_decimal_value[row][col].sign=  value->sign;
  memset((void*)pctx->sql_decimal_value[row][col].buf, '\0',(int)value->len);
  memcpy((void*)pctx->sql_decimal_value[row][col].buf, (void*)value->buf,(int)value->len);

  DBUG_RETURN(false);
}

static int sql_get_double(void * ctx, double value, uint32 decimals)
{
  char buffer[1024];
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_get_double");
  uint row= pctx->num_rows;
  uint col= pctx->current_col;
  pctx->current_col++;

  size_t len= my_snprintf(buffer, sizeof(buffer), "%3.7g", value);

  strncpy(pctx->sql_str_value[row][col], buffer, len);
  pctx->sql_str_len[row][col]= len;

  pctx->sql_double_value[row][col]= value;
  pctx->sql_double_decimals[row][col]= decimals;
 
  DBUG_RETURN(false);
}

static int sql_get_date(void * ctx, const MYSQL_TIME * value)
{
  char buffer[1024];
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_get_date");
  uint row= pctx->num_rows;
  uint col= pctx->current_col;
  pctx->current_col++;

  size_t len= my_snprintf(buffer, sizeof(buffer),
                          "%s%4d-%02d-%02d",
                          value->neg? "-":"",
                          value->year, value->month, value->day);

  strncpy(pctx->sql_str_value[row][col], buffer, len);
  pctx->sql_str_len[row][col]= len;

  pctx->sql_date_value[row][col].year=        value->year;
  pctx->sql_date_value[row][col].month=       value->month;
  pctx->sql_date_value[row][col].day=         value->day;

  pctx->sql_date_value[row][col].hour=        value->hour;
  pctx->sql_date_value[row][col].minute=      value->minute;
  pctx->sql_date_value[row][col].second=      value->second;
  pctx->sql_date_value[row][col].second_part= value->second_part;
  pctx->sql_date_value[row][col].neg=         value->neg;

  DBUG_RETURN(false);
}

static int sql_get_time(void * ctx, const MYSQL_TIME * value, uint decimals)
{
  char buffer[1024];
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_get_time");
  uint row= pctx->num_rows;
  uint col= pctx->current_col;
  pctx->current_col++;

  size_t len= my_snprintf(buffer, sizeof(buffer),
                          "%s%02d:%02d:%02d",
                          value->neg? "-":"",
                          value->day? (value->day*24 + value->hour):value->hour,
                          value->minute, value->second);

  strncpy(pctx->sql_str_value[row][col], buffer, len);
  pctx->sql_str_len[row][col]= len;

  pctx->sql_time_value[row][col].year=        value->year;
  pctx->sql_time_value[row][col].month=       value->month;
  pctx->sql_time_value[row][col].day=         value->day;

  pctx->sql_time_value[row][col].hour=        value->hour;
  pctx->sql_time_value[row][col].minute=      value->minute;
  pctx->sql_time_value[row][col].second=      value->second;
  pctx->sql_time_value[row][col].second_part= value->second_part;
  pctx->sql_time_value[row][col].neg=         value->neg;
  pctx->sql_time_decimals[row][col]=          decimals;

  DBUG_RETURN(false);
}

static int sql_get_datetime(void * ctx, const MYSQL_TIME * value, uint decimals)
{
  char buffer[1024];
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_get_datetime");
  uint row= pctx->num_rows;
  uint col= pctx->current_col;
  pctx->current_col++;

  size_t len= my_snprintf(buffer, sizeof(buffer),
                          "%s%4d-%02d-%02d %02d:%02d:%02d",
                          value->neg? "-":"",
                          value->year, value->month, value->day,
                          value->hour, value->minute, value->second);

  strncpy(pctx->sql_str_value[row][col], buffer, len);
  pctx->sql_str_len[row][col]= len;

  pctx->sql_datetime_value[row][col].year=        value->year;
  pctx->sql_datetime_value[row][col].month=       value->month;
  pctx->sql_datetime_value[row][col].day=         value->day;

  pctx->sql_datetime_value[row][col].hour=        value->hour;
  pctx->sql_datetime_value[row][col].minute=      value->minute;
  pctx->sql_datetime_value[row][col].second=      value->second;
  pctx->sql_datetime_value[row][col].second_part= value->second_part;
  pctx->sql_datetime_value[row][col].neg=         value->neg;
  pctx->sql_datetime_decimals[row][col]=          decimals;

  DBUG_RETURN(false);
}

static int sql_get_string(void * ctx, const char * const value, size_t length,
                          const CHARSET_INFO * const valuecs)
{
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_get_string");
  uint row= pctx->num_rows;
  uint col= pctx->current_col;
  pctx->current_col++;

  strncpy(pctx->sql_str_value[row][col], value, length);
  pctx->sql_str_len[row][col]= length;

  DBUG_RETURN(false);
}

static void sql_handle_ok(void * ctx,
                          uint server_status, uint statement_warn_count,
                          ulonglong affected_rows, ulonglong last_insert_id,
                          const char * const message)
{
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_handle_ok");
  if (!pctx->num_cols)
    pctx->num_rows= 0;
  pctx->server_status=  server_status;
  pctx->warn_count=     statement_warn_count;
  pctx->affected_rows=  affected_rows;
  pctx->last_insert_id= last_insert_id;
  if (message)
    strncpy(pctx->message, message, sizeof(pctx->message));

  DBUG_VOID_RETURN;
}

static void sql_handle_error(void * ctx, uint sql_errno,
                             const char * const err_msg,
                             const char * const sqlstate)
{
  struct st_plugin_ctx *pctx= (struct st_plugin_ctx*) ctx;
  DBUG_ENTER("sql_handle_error");
  pctx->sql_errno=sql_errno;
  if (pctx->sql_errno)
  {
    strcpy(pctx->err_msg,(char *)err_msg);
    strcpy(pctx->sqlstate,(char*)sqlstate);
  }
  pctx->num_rows= 0;
  DBUG_VOID_RETURN;
}

static void sql_shutdown(void *ctx, int shutdown_server)
{
  DBUG_ENTER("sql_shutdown");
  DBUG_VOID_RETURN;
}

const struct st_command_service_cbs sql_cbs=
{
  sql_start_result_metadata,
  sql_field_metadata,
  sql_end_result_metadata,
  sql_start_row,
  sql_end_row,
  sql_abort_row,
  sql_get_client_capabilities,
  sql_get_null,
  sql_get_integer,
  sql_get_longlong,
  sql_get_decimal,
  sql_get_double,
  sql_get_date,
  sql_get_time,
  sql_get_datetime,
  sql_get_string,
  sql_handle_ok,
  sql_handle_error,
  sql_shutdown,
};

struct exec_sql_thread_context {
  const innodb_lock_wait_data *lwd;
  int result_code;
  std::string requested_statements;
  std::string blocking_statements;
};

std::string get_statements_history(MYSQL_SESSION session,
                                   st_plugin_ctx *pctx,
                                   uint32_t thread_id) {
  std::string result;
  COM_DATA cmd;
  pctx->reset();
  char query_buf[1024];
  my_snprintf(query_buf, sizeof(query_buf),
    "SELECT s.SQL_TEXT FROM "
    "performance_schema.events_statements_history s "
    "INNER JOIN "
    "performance_schema.threads t "
    "ON t.THREAD_ID = s.THREAD_ID "
    "WHERE t.PROCESSLIST_ID = %d "
    "UNION "
    "SELECT s.SQL_TEXT FROM "
    "performance_schema.events_statements_current s "
    "INNER JOIN "
    "performance_schema.threads t "
    "ON t.THREAD_ID = s.THREAD_ID "
    "WHERE t.PROCESSLIST_ID = %d",
    thread_id, thread_id);
  cmd.com_query.query= query_buf;
  cmd.com_query.length= strlen(cmd.com_query.query);
  int fail= command_service_run_command(
    session, COM_QUERY, &cmd, &my_charset_utf8_general_ci,
    &sql_cbs, CS_TEXT_REPRESENTATION, pctx);
  if (fail)
  {
    if (!srv_session_close(session))
      my_plugin_log_message(
        &plugin_ptr, MY_ERROR_LEVEL,
        "test_sql_2_sessions - ret code : %d", fail);
  }
  else if (pctx->num_cols) {
    for (uint row= 0; row < pctx->num_rows; row++)
    {
      for (uint col= 0; col < pctx->num_cols; col++)
      {
        result.append(pctx->sql_str_value[row][col]);
      }
      result.append("\n");
    }
  }
  return result;
}

static void exec_sql(exec_sql_thread_context *context) {
  std::unique_ptr<st_plugin_ctx> pctx(new st_plugin_ctx());
  MYSQL_SESSION session = srv_session_open(NULL, pctx.get());
  if (!session) {
    my_plugin_log_message(
      &plugin_ptr, MY_ERROR_LEVEL,
      "Open server session failed.");
      context->result_code = 0;
      return;
  }
  else
    switch_user(session);

  std::string blocking_statements =
    get_statements_history(
      session, pctx.get(), context->lwd->blocking_thread_id);
  std::string requested_statements =
    get_statements_history(
      session, pctx.get(), context->lwd->requested_thread_id);

  std::swap(context->blocking_statements, blocking_statements);
  std::swap(context->requested_statements, requested_statements);

  context->result_code = 1;
  srv_session_close(session);
  return;
}

static void *exec_sql_thread_func(void *arg) {
  exec_sql_thread_context *context =
    static_cast<exec_sql_thread_context*>(arg);

  if (srv_session_init_thread(plugin_ptr))
    my_plugin_log_message(
      &plugin_ptr, MY_ERROR_LEVEL, "srv_session_init_thread failed.");

  exec_sql(context);

  srv_session_deinit_thread();

  return nullptr;
};

static void get_stmts(char *&query, size_t &query_length,
                      char *&endptr, char *&endbuf,
                      size_t &full_outlen,
                      const charset_info_st* general_charset,
                      const std::string &stmts, MYSQL_THD thd) {

  query_length = my_charset_utf8mb4_general_ci.mbmaxlen *
                 stmts.length();

  if (query_length < (size_t) (endbuf - endptr))
  {
    uint errors;
    query_length= my_convert(endptr, query_length,
                             &my_charset_utf8mb4_general_ci,
                             stmts.c_str(),
                             stmts.length(),
                             general_charset, &errors);
    query = endptr;
    endptr += query_length;

    full_outlen += query_length;

    query = escape_string(query, query_length, endptr, endbuf - endptr,
                          &endptr, &full_outlen);
  }
  else
  {
    endptr= endbuf;
    query= escape_string(stmts.c_str(),
                         stmts.length(),
                         endptr, endbuf - endptr, &endptr, &full_outlen);
    full_outlen+= full_outlen * my_charset_utf8mb4_general_ci.mbmaxlen;
  }
}

static
char *audit_log_lock_waits_timeout_record(
  char *buf, size_t buflen,
  MYSQL_THD thd,
  const char *engine,
  const innodb_lock_wait_data &lwd,
  const charset_info_st* general_charset,
  const std::string &requested_statements,
  const std::string &blocking_statements,
  size_t *outlen) {

  char id_str[MAX_RECORD_ID_SIZE];
  char timestamp[MAX_TIMESTAMP_SIZE];
  char *req_stmt;
  size_t req_stmt_length;
  char *block_stmt;
  size_t block_stmt_length;
  char *endptr= buf, *endbuf= buf + buflen;
  size_t full_outlen= 0;

  static const char *format_string[] = {
                     "<AUDIT_RECORD\n"
                     "  NAME=\"%s\"\n"
                     "  RECORD=\"%s\"\n"
                     "  TIMESTAMP=\"%s\"\n"
                     "  ENGINE=\"%s\"\n"
                     "  REQUESTED_TRX_ID=\"%" PRId64 "\"\n"
                     "  REQUESTED_THREAD_ID=\"%" PRId32 "\"\n"
                     "  BLOCKING_TRX_ID=\"%" PRId64 "\"\n"
                     "  BLOCKING_THREAD_ID=\"%" PRId32 "\"\n"
                     "  REQUESTED_STATEMENTS_HISTORY=\"%s\"\n"
                     "  BLOCKING_STATEMENTS_HISTORY=\"%s\"\n"
                     "/>\n",

                     "<AUDIT_RECORD>\n"
                     "  <NAME>%s</NAME>\n"
                     "  <RECORD>%s</RECORD>\n"
                     "  <TIMESTAMP>%s</TIMESTAMP>\n"
                     "  <ENGINE>%s</ENGINE>\n"
                     "  <REQUESTED_TRX_ID>%" PRId64 "</REQUESTED_TRX_ID>\n"
                     "  <REQUESTED_THREAD_ID>%" PRId32 "</REQUESTED_THREAD_ID>\n"
                     "  <BLOCKING_TRX_ID>%" PRId64 "</BLOCKING_TRX_ID>\n"
                     "  <BLOCKING_THREAD_ID>%" PRId32 "</BLOCKING_THREAD_ID>\n"
                     "  <REQUESTED_STATEMENTS_HISTORY>%s</REQUESTED_STATEMENTS_HISTORY>\n"
                     "  <BLOCKING_STATEMENTS_HISTORY>%s</BLOCKING_STATEMENTS_HISTORY>\n"
                     "</AUDIT_RECORD>\n",

                     "{\"audit_record\":"
                       "{\"name\":\"%s\","
                       "\"record\":\"%s\","
                       "\"timestamp\":\"%s\","
                       "\"engine\":\"%s\","
                       "\"requested_trx_id\":\"%" PRId64 "\","
                       "\"requested_thread_id\":\"%" PRId32 "\","
                       "\"blocking_trx_id\":\"%" PRId64 "\","
                       "\"blocking_thread_id\":\"%" PRId32 "\","
                       "\"requested_statements_history\":\"%s\","
                       "\"blocking_statements_history\":\"%s\"}}\n",

                     "\"%s\",\"%s\",\"%s\",\"%s\","
                     "%" PRId64 ",%" PRId32 ","
                     "%" PRId64 ",%" PRId32 ","
                     "\"%s\",\"%s\"\n" };

  get_stmts(req_stmt, req_stmt_length, endptr, endbuf, full_outlen,
    general_charset, requested_statements, thd);
  get_stmts(block_stmt, block_stmt_length, endptr, endbuf, full_outlen,
    general_charset, blocking_statements, thd);

  *outlen= snprintf(endptr, endbuf - endptr,
                    format_string[audit_log_format],
                    "Lock_waits_timeout",
                    make_record_id(id_str, sizeof(id_str)),
                    make_timestamp(timestamp, sizeof(timestamp), time(nullptr)),
                    engine,
                    lwd.requested_trx_id, lwd.requested_thread_id,
                    lwd.blocking_trx_id, lwd.blocking_thread_id,
                    req_stmt, block_stmt);

  /* make sure that record is not truncated */
  DBUG_ASSERT(endptr + *outlen <= buf + buflen);

  return endptr;
}

static void out_lock_waits(MYSQL_THD thd,
                           const char *engine,
                           const innodb_lock_wait_data &lwd,
                           const charset_info_st* general_charset,
                           const std::string &requested_statements,
                           const std::string &blocking_statements) {
  char buf[4096];
  char *log_rec = NULL;
  char *allocated_buf= get_record_buffer(thd, 0);
  size_t len, buflen;
  audit_log_thd_local *local= get_thd_local(thd);

  /* use allocated buffer if available */
  if (allocated_buf != NULL)
  {
    log_rec= allocated_buf;
    buflen= local->record_buffer_size;
  }
  else
  {
    log_rec= buf;
    buflen= sizeof(buf);
  }
  log_rec= audit_log_lock_waits_timeout_record(log_rec, buflen, thd,
                                               engine, lwd,
                                               general_charset,
                                               requested_statements,
                                               blocking_statements,
                                               &len);
  if (len > buflen)
  {
    buflen= len * 4;
    log_rec= audit_log_lock_waits_timeout_record(get_record_buffer(thd, buflen),
                                                 buflen, thd,
                                                 engine, lwd,
                                                 general_charset,
                                                 requested_statements,
                                                 blocking_statements,
                                                 &len);
  }
  if (log_rec)
    audit_log_write(log_rec, len);

}

int process_locks(MYSQL_THD thd,
                  mysql_event_class_t event_class,
                  const void *event) {

  const mysql_event_locks *ev = static_cast<const mysql_event_locks *>(event);

  if (ev->event_subclass != MYSQL_AUDIT_LOCKS_WAIT_TIMEOUT)
    return 0;

  if (!ev->storage_engine_name ||
      strcmp(ev->storage_engine_name, "InnoDB")) {
    my_plugin_log_message(
      &plugin_ptr, MY_ERROR_LEVEL,
      "Only InnoDB locks wait timeout info output is currently implemented");
      return 0;
  }

  my_thread_attr_t attr;          /* Thread attributes */
  my_thread_attr_init(&attr);
  (void) my_thread_attr_setdetachstate(&attr, MY_THREAD_CREATE_JOINABLE);

  exec_sql_thread_context context;
  context.lwd= static_cast<const innodb_lock_wait_data *>(ev->data);

  my_thread_handle thread;

  if (my_thread_create(&thread,
                       &attr,
                       exec_sql_thread_func,
                       &context) != 0)
    my_plugin_log_message(&plugin_ptr,
                          MY_ERROR_LEVEL,
                          "Could not create test session thread");
  else
    my_thread_join(&thread, NULL);

  if (context.result_code)
    out_lock_waits(thd,
                   ev->storage_engine_name,
                   *context.lwd,
                   ev->general_charset,
                   context.requested_statements,
                   context.blocking_statements);
/*
  my_write(STDERR_FILENO,
          (uchar *)context.requesting_statements.c_str(),
          context.requesting_statements.length(),
          MYF(0));
  my_write(STDERR_FILENO,
          (uchar *)context.blocking_statements.c_str(),
          context.blocking_statements.length(),
          MYF(0));
*/
  return context.result_code;
}
