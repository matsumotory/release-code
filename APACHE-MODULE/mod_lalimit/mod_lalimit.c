// -------------------------------------------------------------------
// mod_lalimit.c
//   Control the number of processes in the system run queue
//       averaged over the last 1 minutes.
//   By matsumoto_r Sep 2009 in Japan
//
// Date     2009/09/08
// Version  0.01-beta
//
// change log
// 2009/09/07 0.01 matsumoto_r coding start
// 2009/09/14 0.02 matsumoto_r pre-server-config add "LAlimitEnable ON|OFF"
// 2010/11/23 0.90 matsumoto_r real_path_for_mr() and _analyze_links() added
// 2011/03/08 0.91 matsumoto_r for 1.3 for 2.0 implement
//
// -------------------------------------------------------------------

// -------------------------------------------------------------------
// How To Compile
// [Use DSO]
//  for apache 1.3
//      apxs -c -D__MOD_APACHE1__ mod_lalimit.c
//      cp ./.libs/mod_lalimit.so /usr/local/apache/modules
//
//  for apache 2.x
//      apxs -c -D__MOD_APACHE2__ mod_lalimit.c
//      cp ./.libs/mod_lalimit.so /usr/local/apache2/modules
//
//  for apache 1.3 2.x DEBUG into syslog
//      apxs -c -D__MOD_APACHE1__ -D__MOD_DEBUG__ mod_lalimit.c
//      apxs -c -D__MOD_APACHE2__ -D__MOD_DEBUG__ mod_lalimit.c
//
// <add to  httpd.conf>
// LoadModule lalimit_module libexec/mod_lalimit.so
//
// -------------------------------------------------------------------

// -------------------------------------------------------------------
// How To Use
//
//      log file: /tmp/mod_lalimit.log
//            or #define MOD_LOG_FILE       "/tmp/mod_lalimit.log"
//
//

// [Server Config]
//
// LAlimitEnable <ON|OFF>
//
// -------------------------------------------------------------------
// [Directive Config]
//
// LAlimit <number of Limit Load Average>
//
// - Directory Access Control -
// <Directory "/var/www/html">
//      LAlimit 0.99
// </Directory>
//
// - File Access Control -
// <Files "abc.cgi">
//      LAlimit 10.02
// </Files>
// 
// - Files Regex Access Control -
// <FilesMatch ".*\.cgi$">
//      LAlimit 30
// </FilesMatch>
//
// - File Access Control and Output log -
//      /tmp/mod_lalimit.log
// <Files "mt.cgi">
//      LAlimit 0.51 log
// </Files>
//
// -------------------------------------------------------------------


/* ---------------------------- */
/* --- Include Header Files --- */
/* ---------------------------- */
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "ap_config.h"
#include "http_protocol.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <limits.h>

#if defined (__MOD_APACHE1__) && defined (__MOD_APACHE2__)
#error Ouch!!
#endif

#ifdef __MOD_APACHE1__
#include "ap_alloc.h"
#endif
#ifdef __MOD_APACHE2__
#include "apr_strings.h"
#endif
#ifdef __MOD_DEBUG__
#include <syslog.h>
#define __MOD_NOTICE__
#endif
#ifdef __MOD_NOTICE__
#include <syslog.h>
#endif

char load_version[] = "load_version 0.91";


/* ------------------------ */
/* --- Macro Difinition --- */
/* ------------------------ */
#define LOAD_OK               0
#define LOAD_503             -1
#define LOAD_EXCEPTION       -2

#ifdef __MOD_APACHE1__
#define MOD_LOG_FILE       "/tmp/mod_lalimit.log"
#endif
#ifdef __MOD_APACHE2__
#define MOD_LOG_FILE       "/tmp/mod_lalimit.log"
#endif

#define MOD_LOG_ON         1
#define MOD_LOG_OFF        0
#define MOD_ENABLE_ON      1
#define MOD_ENABLE_OFF     0
#define MAX_SET_LA         100

#ifndef MAXSYMLINKS
#define MAXSYMLINKS        256
#endif

#ifdef __MOD_APACHE2__
#define ap_palloc apr_palloc
#define ap_pcalloc apr_pcalloc
#define ap_psprintf apr_psprintf
#define ap_pstrcat apr_pstrcat
#define ap_pstrdup apr_pstrdup
#define ap_pstrndup apr_pstrndup
#define ap_pvsprintf apr_pvsprintf
#define ap_snprintf apr_snprintf
#define ap_vsnprintf apr_vsnprintf
#endif


/* ----------------------------------- */
/* --- Struct and Typed Definition --- */
/* ----------------------------------- */
typedef struct loadavg_data {

    double now_load;
    double set_load;
    int check_status;

} LA_DATA;

typedef struct lalimit_dir_conf {

    double maxLoadAverageLimit;
    char *set_dir;
    char *full_path;
    int log;

} LALIMIT_CONF;

typedef struct lalimit_server_conf {

    int enable;

} LALIMIT_S_CONF;


/* ----------------------------------- */
/* --- Grobal Variables Definition --- */
/* ----------------------------------- */
int initialized = 0;
char *load_la_log_buf = NULL;
char *trans_la_log_buf = NULL;

#ifdef __MOD_APACHE1__
FILE *load_la_log_fp = NULL;
#endif
#ifdef __MOD_APACHE2__
apr_file_t *load_la_log_fp = NULL;
#endif

#ifdef __MOD_APACHE1__
module MODULE_VAR_EXPORT lalimit_module;
#endif
#ifdef __MOD_APACHE2__
module AP_MODULE_DECLARE_DATA lalimit_module;
#endif


/* --------------------------------------- */
/* --- Debug in SYSLOG Logging Routine --- */
/* --------------------------------------- */
#ifdef __MOD_DEBUG__
char *mr_debug_la_log_buf = NULL;
#ifdef __MOD_APACHE1__
void MOD_DEBUG_SYSLOG(const char *key, const char *msg, pool *p)
#endif
#ifdef __MOD_APACHE2__
void MOD_DEBUG_SYSLOG(const char *key, const char *msg, apr_pool_t *p)
#endif
{
    char *mr_buf = NULL;

    mr_buf = (char *)ap_psprintf(p,"%s%s", key, msg);
                                    
    openlog(NULL, LOG_PID, LOG_SYSLOG);
    syslog(LOG_DEBUG, mr_buf);
    closelog();
}
#endif


/* ---------------------------------------- */
/* --- Notice in SYSLOG Logging Routine --- */
/* ---------------------------------------- */
#ifdef __MOD_NOTICE__
char *mr_notice_la_log_buf = NULL;
#ifdef __MOD_APACHE1__
void MOD_NOTICE_SYSLOG(const char *key, const char *msg, pool *p)
#endif
#ifdef __MOD_APACHE2__
void MOD_NOTICE_SYSLOG(const char *key, const char *msg, apr_pool_t *p)
#endif
{
    char *mr_buf = NULL;

    mr_buf = (char *)ap_psprintf(p,"%s%s", key, msg);
    openlog(NULL, LOG_PID, LOG_SYSLOG);
    syslog(LOG_INFO, mr_buf);
    closelog();
}
#endif



/* ------------------------------------------- */
/* --- Request Transaction Logging Routine --- */
/* ------------------------------------------- */
#ifdef __MOD_APACHE1__
void _load_trans_logging(LALIMIT_CONF *pLalimitConf, const char *msg, LA_DATA *pAnalysisLA, const char *trans_info, pool *p)
#endif
#ifdef __MOD_APACHE2__
void _load_trans_logging(LALIMIT_CONF *pLalimitConf, const char *msg, LA_DATA *pAnalysisLA, const char *trans_info, apr_pool_t *p)
#endif
{
    int len;
    time_t t;
    char *log_time;
     
    if(pLalimitConf->log == MOD_LOG_ON){
        time(&t);
        log_time = (char *)ctime(&t);
        len = strlen(log_time);
        log_time[len - 1] = '\0';
         
        load_la_log_buf = (char *)ap_psprintf(p, 
            "[%s] pid=%d %s current_loadavg=\"%.2f\" config_loadavg=\"%.2f\" config_dir=\"%s\" %s\n",
            log_time,
            getpid(),
            msg,
            pAnalysisLA->now_load,
            pAnalysisLA->set_load,
            pLalimitConf->set_dir,
            trans_info);
         
#ifdef __MOD_APACHE1__
        fputs(load_la_log_buf, load_la_log_fp);
        fflush(load_la_log_fp);
#endif
#ifdef __MOD_APACHE2__
        apr_file_puts(load_la_log_buf, load_la_log_fp);
        apr_file_flush(load_la_log_fp);
#endif
    } 
}

/* ------------------------------------------- */
/* --- Init Routine or ap_hook_post_config --- */
/* ------------------------------------------- */
#ifdef __MOD_APACHE1__
static void lalimit_init(server_rec *server, pool *p)
#endif
#ifdef __MOD_APACHE2__
static int lalimit_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *server)
#endif
{
    struct stat;

#ifdef __MOD_DEBUG__
    MOD_DEBUG_SYSLOG("lalimit_init: ", "start", p);
#endif

#ifdef __MOD_APACHE1__
    load_la_log_fp = (FILE *)ap_pfopen(p, MOD_LOG_FILE, "a");
    if(load_la_log_fp == NULL){
        return;
    }
#endif
#ifdef __MOD_APACHE2__
    if(apr_file_open(&load_la_log_fp, MOD_LOG_FILE, APR_WRITE|APR_APPEND|APR_CREATE,
           APR_OS_DEFAULT, p) != APR_SUCCESS){
        return OK;
    }
#endif

    initialized = 1;

#ifdef __MOD_DEBUG__
    MOD_DEBUG_SYSLOG("lalimit_init: ", "end", p);
#endif

#ifdef __MOD_APACHE1__
    return;
#endif
#ifdef __MOD_APACHE2__
    return OK;
#endif
}

/* ------------------------- */
/* --- Create Dir Config --- */
/* ------------------------- */
#ifdef __MOD_APACHE1__
static void *lalimit_create_dir_config(pool *p, char *dir)
#endif
#ifdef __MOD_APACHE2__
static void *lalimit_create_dir_config(apr_pool_t *p, char *dir)
#endif
{
    LALIMIT_CONF *pLalimitConf =
        (LALIMIT_CONF *)ap_palloc(p, sizeof(LALIMIT_CONF));

#ifdef __MOD_DEBUG__
    mr_debug_la_log_buf = (char *)ap_psprintf(p,
        "dir=\"%s\"",
        dir);
    MOD_DEBUG_SYSLOG("lalimit_create_dir_config: ", mr_debug_la_log_buf, p);
#endif

    pLalimitConf->maxLoadAverageLimit = 0;
    pLalimitConf->set_dir             = ap_pstrdup(p, dir);
    pLalimitConf->full_path           = NULL;
    pLalimitConf->log                 = MOD_LOG_OFF;
  
    return pLalimitConf;
}


/* ---------------------------- */
/* --- Create Server Config --- */
/* ---------------------------- */
#ifdef __MOD_APACHE1__
static void *lalimit_create_server_config(pool *p, server_rec *s)
#endif
#ifdef __MOD_APACHE2__
static void *lalimit_create_server_config(apr_pool_t *p, server_rec *s)
#endif
{
    LALIMIT_S_CONF *pLalimitServerConf = 
        (LALIMIT_S_CONF *)ap_palloc(p, sizeof(LALIMIT_S_CONF));

    pLalimitServerConf->enable = MOD_ENABLE_OFF;

    return pLalimitServerConf;
}


/* ----------------------------------------------------------------------------- */
/* --- Set ServerDirective in Struct Command_rec * Cmds (set_enable_lalimit) --- */
/* ----------------------------------------------------------------------------- */
static const char *
set_enable_lalimit(cmd_parms *cmd, void *server_config_fmt, char *arg1)
{
    char *q, *ar;

    LALIMIT_S_CONF *pLalimitServerConf;
    pLalimitServerConf = 
        (LALIMIT_S_CONF *)ap_get_module_config(cmd->server->module_config, &lalimit_module);

    q = ap_pcalloc(cmd->pool, sizeof(char));
    q = strtok(arg1, " ");
    ar = ap_pstrdup(cmd->pool, q);

    if (strcmp(q, "ON") == 0)
        pLalimitServerConf->enable = MOD_ENABLE_ON;
    else if (strcmp(q, "OFF") == 0)
        pLalimitServerConf->enable = MOD_ENABLE_OFF;
    else
        return "invalid conf: LAlimitEnable ON|OFF";
    
    if ((q = strtok(NULL, " ")) != NULL)
        return "invalid conf(arg count > 1): LAlimitEnable ON|OFF";

#ifdef __MOD_DEBUG__
    mr_debug_la_log_buf = ap_psprintf(cmd->pool,
        "[config parser] LAlimitEnable=%s pLalimitServerConf->enable=\"%d\"",
        ar,
        pLalimitServerConf->enable);
    MOD_DEBUG_SYSLOG("set_enable_lalimit: ", mr_debug_la_log_buf, cmd->pool);
#endif

    ar = NULL;

    return NULL;
}


/* --------------------------------------------------------------- */
/* --- Set Directive in Struct Command_rec * Cmds (set_lalimit)--- */
/* --------------------------------------------------------------- */


static const char *
set_lalimit(cmd_parms *cmd, void *dir_config_fmt, char *arg1, char *arg2_opt, char *arg3_opt)
{
    double set_value;

    LALIMIT_CONF *pLalimitConf = (LALIMIT_CONF *)dir_config_fmt;

    set_value = atof(arg1);

    if (set_value > MAX_SET_LA || set_value < 0)
        return "invalid value: LAlimit arg1 [ 0 < LAlimit < 101 ]";

    if (arg2_opt == NULL)
        pLalimitConf->log = MOD_LOG_OFF;
    else if (strcmp(arg2_opt, "log") == 0) {
        pLalimitConf->log = MOD_LOG_ON;
        if (arg3_opt != NULL)
            return "invalid conf (arg2 == log && arg3 != NULL) : 'usage: LAlimit <set_average> (log|full_path) (log)' [ 0 < set_average < 101 ]";
    }
    else if (strcmp(arg2_opt, "log") != 0) {
        pLalimitConf->full_path = ap_pstrdup(cmd->pool, arg2_opt);

        if (arg3_opt == NULL)
            pLalimitConf->log = MOD_LOG_OFF;
        else if (strcmp(arg3_opt, "log") == 0)
            pLalimitConf->log = MOD_LOG_ON;
        else if (strcmp(arg3_opt, "log") != 0)
            return "invalid conf (arg3 != log) : 'usage: LAlimit <set_average> (log|full_path) (log)' [ 0 < set_average < 101 ]";
        else
            return "invalid conf : 'usage: LAlimit <set_average> (log|full_path) (log)' [ 0 < set_average < 101 ]";
    }
    else
        return "invalid conf : 'usage: LAlimit <set_average> (log|full_path) (log)' [ 0 < set_average < 101 ]";
    
    pLalimitConf->maxLoadAverageLimit = set_value;

#ifdef __MOD_DEBUG__
    mr_debug_la_log_buf = ap_psprintf(cmd->pool,
        "[config parser] SET_OBJ=\"%s\" LAlimit=\"%.2f\" full_path=[%s] log=\"%d\"",
        cmd->path,
        pLalimitConf->maxLoadAverageLimit,
        pLalimitConf->full_path,
        pLalimitConf->log
    );
    MOD_DEBUG_SYSLOG("set_lalimit: ", mr_debug_la_log_buf, cmd->pool);
#endif

    return NULL;
}


/* ---------------------- */
/* --- Access Checker --- */
/* ---------------------- */
static LA_DATA *
#ifdef __MOD_APACHE1__
_loadavg_check(LALIMIT_CONF *pLalimitConf, pool *p)
#endif
#ifdef __MOD_APACHE2__
_loadavg_check(LALIMIT_CONF *pLalimitConf, apr_pool_t *p)
#endif
{
    LA_DATA *pAnalysisLA;
    struct sysinfo info;
    double av1;
    double shift = (1 << SI_LOAD_SHIFT);

    pAnalysisLA =
        (LA_DATA *)ap_pcalloc(p, sizeof(LA_DATA));

    if (sysinfo(&info) == -1) {
        pAnalysisLA->now_load = 0;
        pAnalysisLA->set_load = pLalimitConf->maxLoadAverageLimit;
        pAnalysisLA->check_status = LOAD_EXCEPTION;
        return pAnalysisLA;
    }

    av1 = info.loads[0] / shift;

#ifdef __MOD_DEBUG__
    mr_debug_la_log_buf = (char *)ap_psprintf(p,
        "now_load_avg =[%.2f] set_load_avg = [%.2f]",
        av1,
        pLalimitConf->maxLoadAverageLimit);
    MOD_DEBUG_SYSLOG("_loadavg_check: ", mr_debug_la_log_buf, p);
#endif

    pAnalysisLA->now_load = av1;
    pAnalysisLA->set_load = pLalimitConf->maxLoadAverageLimit;

    if (pLalimitConf->maxLoadAverageLimit <= av1)
        pAnalysisLA->check_status = LOAD_503;
    else
        pAnalysisLA->check_status = LOAD_OK;

    return pAnalysisLA;
}


// myrealpath on canonicalize.c was changed by matsumoto_r in 2010/01/30
static char *
#ifdef __MOD_APACHE1__
realpath_for_mr(const char *path, char *resolved_path, int maxreslth, pool *p) {
#endif
#ifdef __MOD_APACHE2__
realpath_for_mr(const char *path, char *resolved_path, int maxreslth, apr_pool_t *p) {
#endif

    int readlinks = 0;
    int n;

    char *npath;
    char link_path[PATH_MAX+1];
    char *buf;

    buf = ap_pcalloc(p, sizeof(char *));
    npath = resolved_path;

    if (*path != '/') {
        if (!getcwd(npath, maxreslth-2))
            return NULL;
        npath += strlen(npath);
        if (npath[-1] != '/')
            *npath++ = '/';
    } else {
        *npath++ = '/';
        path++;
    }

    while (*path != '\0') {

        if (*path == '/') {
            path++;
            continue;
        }

        if (*path == '.' && (path[1] == '\0' || path[1] == '/')) {
            path++;
            continue;
        }

        if (*path == '.' && path[1] == '.' &&
            (path[2] == '\0' || path[2] == '/')) {
            path += 2;
            while (npath > resolved_path+1 &&
                   (--npath)[-1] != '/')
                ;
            continue;
        }

        while (*path != '\0' && *path != '/') {
            if (npath-resolved_path > maxreslth-2) {
                errno = ENAMETOOLONG;
                return NULL;
            }
            *npath++ = *path++;
        }

        if (readlinks++ > MAXSYMLINKS) {
            errno = ELOOP;
            return NULL;
        }

        *npath = '\0';
        n = readlink(resolved_path, link_path, PATH_MAX);
        if (n < 0) {
            if (errno != EINVAL) {
                return NULL;
            }
        } else {
            int m;
            char *newbuf;

            link_path[n] = '\0';
            if (*link_path == '/')
                npath = resolved_path;
            else
                while (*(--npath) != '/')
                    ;

            m = strlen(path);
            newbuf = ap_pcalloc(p, m + n + 1);
            memcpy(newbuf, link_path, n);
            memcpy(newbuf + n, path, m + 1);
            path = buf = newbuf;
        }
        *npath++ = '/';
    }

    if (npath != resolved_path+1 && npath[-1] == '/')
        npath--;

    *npath = '\0';

    return resolved_path;

}


#ifdef __MOD_APACHE1__
static char *_analyze_link(char *access_path, pool *p)
#endif
#ifdef __MOD_APACHE2__
static char *_analyze_link(char *access_path, apr_pool_t *p)
#endif
{
    char *real_path;

    real_path = (char *)ap_pcalloc(p, sizeof(char *) * PATH_MAX + 1);

    if( realpath_for_mr(access_path, real_path, PATH_MAX, p) == NULL ){
#ifdef __MOD_DEBUG__
        MOD_DEBUG_SYSLOG("_analyze_link: ", "realpath_for_mr analyze fail. return access_path", p);
#endif
        return access_path;
    }
#ifdef __MOD_DEBUG__
    mr_debug_la_log_buf = ap_psprintf(p,
            "Analyze Path: access_path=[%s] real_path=[%s]"
            , access_path
            , real_path
    );

    MOD_DEBUG_SYSLOG("lalimit: _analyze_link: ", mr_debug_la_log_buf, p);
#endif
    
    return real_path;
}


static int lalimit_access_checker(request_rec *r)
{ 
    LALIMIT_S_CONF *pLalimitServerConf;
    LALIMIT_CONF *pLalimitConf;
    LA_DATA *pAnalysisLA;
    struct stat sb;
    char *real_path;

    pLalimitServerConf = 
        (LALIMIT_S_CONF *)ap_get_module_config(r->server->module_config, &lalimit_module);

    pLalimitConf =
        (LALIMIT_CONF *)ap_get_module_config(r->per_dir_config, &lalimit_module);
    pAnalysisLA = (LA_DATA *)ap_pcalloc(r->pool, sizeof(LA_DATA));

#ifdef __MOD_DEBUG__
    mr_debug_la_log_buf = ap_psprintf(r->pool,
        "Enable=\"%d\" LAlimit=\"%.2f\" SET_OBJ =\"%s\" LOG=\"%d\" URI=\"%s\" FILE=\"%s\" REQ=\"%s\" M=\"%x\" P=\"%x\" N=\"%x\"",
        pLalimitServerConf->enable,
        pLalimitConf->maxLoadAverageLimit,
        pLalimitConf->set_dir,
        pLalimitConf->log,
        r->uri,
        r->filename,
        r->the_request,
        r->main,
        r->prev,
        r->next);

    MOD_DEBUG_SYSLOG("lalimit_access_checker: ", mr_debug_la_log_buf, r->pool);
#endif

    if (pLalimitServerConf->enable == 0) { 
#ifdef __MOD_DEBUG__
        MOD_DEBUG_SYSLOG("lalimit_access_checker: ", "... lalimit_enable == 0. skipped.", r->pool);
#endif
        return OK;
    }

#ifdef __MOD_DEBUG__
    MOD_DEBUG_SYSLOG("lalimit_access_checker: ", "checking ...", r->pool);
#endif

    if (initialized == 0) { 
#ifdef __MOD_DEBUG__
        MOD_DEBUG_SYSLOG("lalimit_access_checker: ", "... initialized == 0. skipped.", r->pool);
#endif
        return OK;
    }

    if(pLalimitConf->maxLoadAverageLimit <= 0){
#ifdef __MOD_DEBUG__
        MOD_DEBUG_SYSLOG("lalimit_access_checker: ", "... not match config. skipped.", r->pool);
#endif
        return OK;
    }
#ifdef __MOD_APACHE1__
    if (r->main) {
#ifdef __MOD_DEBUG__
        MOD_DEBUG_SYSLOG("lalimit_access_checker: ", "... r->main is no null.", r->pool);
#endif
        return OK;
    }
#endif

#ifdef __MOD_APACHE2__
    if (r->main && (stat(r->filename, &sb) == -1) && errno == ENOENT) {
#ifdef __MOD_DEBUG__
        MOD_DEBUG_SYSLOG("lalimit_access_checker: ", "... r->main is no null.", r->pool);
#endif
       return OK;
    }
#endif

#ifdef __MOD_DEBUG__
    MOD_DEBUG_SYSLOG("lalimit_access_checker: ", "Match Config!!", r->pool);
    mr_debug_la_log_buf = ap_psprintf(r->pool,
        "[Match Config] SetDirective=\"%s\" full_path_match=[%s] LAlimit=\"%.2f\" log=\"%d\"",
        pLalimitConf->set_dir,
        pLalimitConf->full_path,
        pLalimitConf->maxLoadAverageLimit,
        pLalimitConf->log);
    MOD_DEBUG_SYSLOG("lalimit_access_checker: ", mr_debug_la_log_buf, r->pool);
#endif

    if (pLalimitConf->full_path != NULL) {
        real_path = (char *)_analyze_link(r->filename, r->pool);
	if (strcmp(pLalimitConf->full_path, real_path) != 0) {

#ifdef __MOD_DEBUG__
            MOD_DEBUG_SYSLOG("lalimit_access_checker: ", "... full_path not match.", r->pool);
#endif

            return OK;
        }

#ifdef __MOD_DEBUG__
        mr_debug_la_log_buf = ap_psprintf(r->pool,
                "PATH INFO: access_path=[%s] real_path=[%s] config_path=[%s]"
                , r->filename
                , real_path
                , pLalimitConf->full_path
        );

        MOD_DEBUG_SYSLOG("lalimit_access_checker: ", "FULL PATH MATCH: real_path <=> config_path", r->pool);
        MOD_DEBUG_SYSLOG("lalimit_access_checker: ", mr_debug_la_log_buf, r->pool);
#endif

    }
   
    if (pLalimitConf->maxLoadAverageLimit > 0) {
        pAnalysisLA = _loadavg_check(pLalimitConf, r->pool);
        trans_la_log_buf = ap_psprintf(r->pool,
            "access_path=\"%s\"",
            r->filename);

        if (pAnalysisLA->check_status == LOAD_OK) {
#ifdef __MOD_DEBUG__
            MOD_DEBUG_SYSLOG("lalimit_access_checker: ", "return OK", r->pool);
#endif
            _load_trans_logging(pLalimitConf, "LA-LIMIT RESULT: OK", pAnalysisLA, trans_la_log_buf, r->pool);
        } else if (pAnalysisLA->check_status == LOAD_503) {
#ifdef __MOD_DEBUG__
            MOD_DEBUG_SYSLOG("lalimit_access_checker: ", "return 503", r->pool);
#endif

#ifdef __MOD_NOTICE__
            mr_notice_la_log_buf = ap_psprintf(r->pool,
                "Returnig 503 on mod_lalimit: SetDirective=\"%s\" LAlimit=\"%.2f\" NowLoadAverage=\"%.2f\": %s",
                pLalimitConf->set_dir,
                pLalimitConf->maxLoadAverageLimit,
                pAnalysisLA->now_load,
                trans_la_log_buf);
            MOD_NOTICE_SYSLOG("lalimit_access_checker: ", mr_notice_la_log_buf, r->pool);
#endif
            _load_trans_logging(pLalimitConf, "LA-LIMIT RESULT:503", pAnalysisLA, trans_la_log_buf, r->pool);
        } else if(pAnalysisLA->check_status == LOAD_EXCEPTION) {
#ifdef __MOD_DEBUG__
            MOD_DEBUG_SYSLOG("lalimit_access_checker: ", "return EXC", r->pool);
#endif
            _load_trans_logging(pLalimitConf, "LA-LIMIT RESULT:EXC", pAnalysisLA, trans_la_log_buf, r->pool);
        }
    }

#ifdef __MOD_DEBUG__
    MOD_DEBUG_SYSLOG("lalimit_access_checker:", " end", r->pool);
#endif


    if (pAnalysisLA->check_status == LOAD_503) {
        return HTTP_SERVICE_UNAVAILABLE;
    } else {
        return OK;
    }
}

/* ------------------- */
/* --- Command_rec --- */
/* ------------------- */
#ifdef __MOD_APACHE1__
    static const command_rec lalimit_cmds[] = {
        {"LAlimit", 
            set_lalimit, 
            0, 
            ACCESS_CONF,
            RAW_ARGS, 
            "Set return 503 over setting Load Average." },
        {"LAlimitEnable", 
            (void *)set_enable_lalimit, 
            0, 
            RSRC_CONF,
            RAW_ARGS, 
            "Set Enable LAlimit." },
        {NULL}
    };
#endif
#ifdef __MOD_APACHE2__
    static const command_rec lalimit_cmds[] = {
        AP_INIT_TAKE123("LAlimit", (void *)set_lalimit, NULL, ACCESS_CONF|OR_LIMIT, "Set return 503 over setting Load Average."),
        AP_INIT_TAKE1("LAlimitEnable", (void *)set_enable_lalimit, NULL, RSRC_CONF, "Set Enable LAlimit."),
        {NULL}
    };
#endif

/* -------------- */
/* --- Module --- */
/* -------------- */
#ifdef __MOD_APACHE1__
module MODULE_VAR_EXPORT lalimit_module = {
       STANDARD_MODULE_STUFF,             // Standard stuff
       lalimit_init,                      // init routine
       lalimit_create_dir_config,         // create dir config
       0,                                 // merge dir config
       lalimit_create_server_config,      // create server config
       0,                                 // merge server config
       lalimit_cmds,                      // struct command_rec * cmds
       0,                                 // struct handler_rec * handlers
       0,                                 // translate handler
       0,                                 // ap_check_user_id
       0,                                 // auth_checker
       lalimit_access_checker,            // access_checker
       0,                                 // type checker
       0,                                 // fixer_upper
       0,                                 // logger
       0,                                 // header_parser
       0,                                 // child_init
       0,                                 // child_exit
       0                                  // post_read_request
};
#endif

#ifdef __MOD_APACHE2__
static void lalimit_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config((void*)lalimit_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(lalimit_access_checker, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA lalimit_module = {
    STANDARD20_MODULE_STUFF,
    lalimit_create_dir_config,              /* create per-dir    config structures */
    NULL,                                   /* merge  per-dir    config structures */
    (void *)lalimit_create_server_config,   /* create per-server config structures */
    NULL,                                   /* merge  per-server config structures */
    lalimit_cmds,                           /* table of config file commands       */
    lalimit_register_hooks                  /* register hooks                      */
};
#endif
