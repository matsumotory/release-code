/*
// -------------------------------------------------------------------
// mod_vlimitconn 0.04
//     Control the number of references from the same IP address to documentroot
//          or the number of references to vhosts.
//
// Original code is "mod_limitipconn.c 0.23"
//     By David Jao and Niklas Edmundsson
//     Copyright (C) 2000-2008
//
// Fixed, Modified And Added By Matsumoto_r
// Date     2010/02/04
// Version  0.04
//
// change log
//  2010/02/04 VlimitConnIP create matsumoto_r 0.01
//  2010/02/08 VlimitConnVhost create matsumoto_r 0.02
//  2010/02/15 vlimitconn_logging() create matsumoto_r 0.03
//  2010/02/16 VLIMITCONN_DEBUG_SYSLOG() create matsumoto_r 0.04
//
// -------------------------------------------------------------------

// -------------------------------------------------------------------
// How To Compile
// [Use DSO]
// apxs -c mod_vlimitconn.c
// cp ./.libs/mod_vlimitconn.so /usr/local/apache2/modules
//
// <add to  httpd.conf>
// LoadModule vlimitconn_module modules/mod_vlimitconn.so
//
// -------------------------------------------------------------------

// -------------------------------------------------------------------
// How To Use
//
//      log file: /tmp/mod_vlimitconn.log
//       or   #define VLIMITCONN_LOG_FILE            "/tmp/mod_vlimitconn.log"
//            #define VLIMITCONN_LOG_FLAG_FILE       "/tmp/VLIMITCONN_LOG"
//            #define VLIMITCONN_DEBUG_FLAG_FILE     "/tmp/VLIMITCONN_DEBUG"
//
//      if touch /tmp/VLIMITCONN_LOG, vlimitconn log into /tmp/mod_vlimitconn.log.
//      if touch /tmp/VLIMITCONN_DEBUG, vlimitconn debug log into syslog.
//
//
// ExtendedStatus On -> for mod_status
//
// VlimitConnIP <number of MaxConnectionsPerHost to DocumentRoot> (RealPath of DocumentRoot)
//
//  <Directory "/www/hoge/huga/001">
//       VlimitConnIP 10
//  </Directory>
//
//  or
//
//  VlimitConnIP 10 /www/hoge/huga/001
//
// or
//
//  write /www/hoge/huga/001/.htaccess
//  VlimitConnIP 10
//
//
// VlimitConnVhost <number of MaxConnectionsPerVhost> (RealPath of DocumentRoot)
//
//  VlimitConnVhost 10 /www/hoge/huga/001
//
// or
//
//  write /www/hoge/huga/001/.htaccess
//  VlimitConnVhost 10
// -------------------------------------------------------------------
*/

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_main.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "apr_strings.h"
#include "scoreboard.h"
#include <libgen.h>
#include <limits.h>
#include <unistd.h>

#define MODULE_NAME                     "mod_vlimitconn"
#define MODULE_VERSION                  "0.04"
#define MAXSYMLINKS                     256
#define SET_VLIMITCONNDEFAULT          0
#define SET_VLIMITCONNIP               1
#define SET_VLIMITCONNVHOST            2
#define VLIMITCONN_LOG_FILE            "/tmp/mod_vlimitconn.log"
#define VLIMITCONN_LOG_FLAG_FILE       "/tmp/VLIMITCONN_LOG"
#define VLIMITCONN_DEBUG_FLAG_FILE     "/tmp/VLIMITCONN_DEBUG"


module AP_MODULE_DECLARE_DATA vlimitconn_module;
static int vlimitconn_server_limit, vlimitconn_thread_limit;
apr_file_t *vlimitconn_log_fp = NULL;

typedef struct {

    signed int type;              /* max number of connections per IP */
    signed int ip_limit;          /* max number of connections per IP */
    signed int vhost_limit;       /* max number of connections per IP */
    char *full_path;              /* option docroot realpath */

} vlimitconn_config;


/* --------------------------------------- */
/* --- Debug in SYSLOG Logging Routine --- */
/* --------------------------------------- */
char *vlimitconn_debug_log_buf = NULL;
static int VLIMITCONN_DEBUG_SYSLOG(const char *key, const char *msg, apr_pool_t *p)
{
#ifdef __MOD_DEBUG__
    char *fs_buf = NULL;

    if (access(VLIMITCONN_DEBUG_FLAG_FILE, F_OK) == 0) {
        fs_buf = (char *)apr_psprintf(p, MODULE_NAME ": %s%s", key, msg);

        openlog(NULL, LOG_PID, LOG_SYSLOG);
        syslog(LOG_DEBUG, fs_buf);
        closelog();

        return 0;
    }

    return -1;
#endif
}


/* ------------------------------------------- */
/* --- Request Transaction Logging Routine --- */
/* ------------------------------------------- */
static int vlimitconn_logging(const char *msg, 
                        const char *address, 
                        const char *vhost, 
                        vlimitconn_config *cfg, 
                        int ip_count, 
                        int vhost_count, 
                        const char *filename, 
                        apr_pool_t *p)
{
    int len;
    time_t t;
    char *log_time;
    char *type;
    char *vlimitconn_log_buf;

    if (access(VLIMITCONN_LOG_FLAG_FILE, F_OK) == 0) {
        time(&t);
        log_time = (char *)ctime(&t);
        len = strlen(log_time);
        log_time[len - 1] = '\0';

        /*
        if (cfg->type == SET_VLIMITCONNIP)
            type = apr_pstrdup(p, "VlimitConnIP");
        else if (cfg->type == SET_VLIMITCONNVHOST)
            type = apr_pstrdup(p, "VlimitConnVhost");
        */

        type = apr_pstrdup(p, "VlimitConn");

        vlimitconn_log_buf = (char *)apr_psprintf(p
            , "[%s] pid=[%d] vhost=[%s] client=[%s] %s %s ip_count: %d/%d vhost_count: %d/%d file=[%s] \n"
            , log_time
            , getpid()
            , vhost
            , address
            , type
            , msg
            , ip_count
            , cfg->ip_limit
            , vhost_count
            , cfg->vhost_limit
            , filename
        );

        apr_file_puts(vlimitconn_log_buf, vlimitconn_log_fp);
        apr_file_flush(vlimitconn_log_fp);

        return 0;
    }
    
    return -1;
}


/* ----------------------------------- */
/* --- Create Share Config Routine --- */
/* ----------------------------------- */
static vlimitconn_config *create_share_config(apr_pool_t *p)
{
    vlimitconn_config *cfg = 
        (vlimitconn_config *)apr_pcalloc(p, sizeof (*cfg));

    /* default configuration: no limit, and both arrays are empty */
    cfg->type        = SET_VLIMITCONNDEFAULT;
    cfg->ip_limit    = 0;
    cfg->vhost_limit = 0;
    cfg->full_path   = NULL;

    return cfg;
}


/* ------------------------------------ */
/* --- Create Server Config Routine --- */
/* ------------------------------------ */
/* Create per-server configuration structure. Used by the quick handler. */
static void *vlimitconn_create_server_config(apr_pool_t *p, server_rec *s)
{
    VLIMITCONN_DEBUG_SYSLOG("mod_vlimitconn: ", "vlimitconn_create_server_config exec.", p);
    return create_share_config(p);
}


/* --------------------------------- */
/* --- Create Dir Config Routine --- */
/* --------------------------------- */
/* Create per-directory configuration structure. Used by the normal handler. */
static void *vlimitconn_create_dir_config(apr_pool_t *p, char *path)
{
    return create_share_config(p);
}


/* ---------------------------------------------------------------------- */
/* --- Check Connections from Clinets to Vhosts in ScoreBoard Routine --- */
/* ---------------------------------------------------------------------- */
/* Generic function to check a request against a config. */
static int vlimitconn_check_limit(request_rec *r, vlimitconn_config *cfg)
{

    const char *address;
    const char *header_name;

    /* loop index variables */
    int i;
    int j;

    /* running count of number of connections from this address */
    int ip_count    = 0;
    int vhost_count = 0;

    /* scoreboard data structure */
    worker_score *ws_record;

    /* We decline to handle subrequests: otherwise, in the next step we
     * could get into an infinite loop. */
    if (!ap_is_initial_req(r)) {
        VLIMITCONN_DEBUG_SYSLOG("vlimitconn_check_limit: ", "SKIPPED: Not initial request", r->pool);
        return DECLINED;
    }

    /* A limit value of 0 or less, by convention, means no limit. */
    if (cfg->ip_limit <= 0 && cfg->vhost_limit <= 0) {
        VLIMITCONN_DEBUG_SYSLOG("vlimitconn_check_limit: ", "SKIPPED: cfg->ip_limit <= 0 && cfg->vhost_limit <= 0", r->pool);
        return DECLINED;
    }

    address     = r->connection->remote_ip;
    header_name = apr_table_get(r->headers_in, "HOST");

    vlimitconn_debug_log_buf = apr_psprintf(r->pool, "client info: address=(%s) header_name=(%s)"
        , address
        , header_name
    );
    VLIMITCONN_DEBUG_SYSLOG("vlimitconn_check_limit: ", vlimitconn_debug_log_buf, r->pool);

    /* Count up the number of connections we are handling right now from this IP address */
    for (i = 0; i < vlimitconn_server_limit; ++i) {
      for (j = 0; j < vlimitconn_thread_limit; ++j) {
        ws_record = ap_get_scoreboard_worker(i, j);

        switch (ws_record->status) {
            case SERVER_BUSY_READ:
            case SERVER_BUSY_WRITE:
            case SERVER_BUSY_KEEPALIVE:
            case SERVER_BUSY_LOG:
            case SERVER_BUSY_DNS:
            case SERVER_CLOSING:
            case SERVER_GRACEFUL:
                if (strcmp(header_name, ws_record->vhost) == 0) {

                    vlimitconn_debug_log_buf = apr_psprintf(r->pool
                        , "match vhost: header_name=(%s) <=> ws_record->vhost=(%s)"
                        , header_name
                        , ws_record->vhost
                    );
                    VLIMITCONN_DEBUG_SYSLOG("vlimitconn_check_limit: ", vlimitconn_debug_log_buf, r->pool);

                    //if (cfg->type == SET_VLIMITCONNVHOST) {
                        VLIMITCONN_DEBUG_SYSLOG("vlimitconn_check_limit: ", "type VHOST: vhost_count++", r->pool);
                        vhost_count++;
                    //} else if (cfg->type == SET_VLIMITCONNIP) {
                        
                        if (strcmp(address, ws_record->client) == 0) {

                            vlimitconn_debug_log_buf = apr_psprintf(r->pool
                                , "match client: address=(%s) <=> ws_record->client=(%s)"
                                , address
                                , ws_record->client
                            );
                            VLIMITCONN_DEBUG_SYSLOG("vlimitconn_check_limit: ", vlimitconn_debug_log_buf, r->pool);
                            VLIMITCONN_DEBUG_SYSLOG("vlimitconn_check_limit: ", "type IP: ip_count++", r->pool);
                            ip_count++;
                        }
                    //}
                    break;
                }

            default:
                break;
        }
      }
    }

    vlimitconn_debug_log_buf = apr_psprintf(r->pool
        , "vhost: %s  uri: %s  ip_count: %d/%d vhost_count: %d/%d"
        , r->server->server_hostname
        , r->uri
        , ip_count
        , cfg->ip_limit
        , vhost_count
        , cfg->vhost_limit
    );
    VLIMITCONN_DEBUG_SYSLOG("vlimitconn_check_limit: ", vlimitconn_debug_log_buf, r->pool);

    if (ip_count > cfg->ip_limit) {
        vlimitconn_debug_log_buf = apr_psprintf(r->pool
            , "Rejected, too many connections from this host(%s) to the vhost(%s) by VlimitConnIP[ip_limig=(%d) docroot=(%s)]."
            , address
            , header_name
            , cfg->ip_limit
            , cfg->full_path
        );
        VLIMITCONN_DEBUG_SYSLOG("vlimitconn_check_limit: ", vlimitconn_debug_log_buf, r->pool);

        vlimitconn_logging("RESULT: 503", address, header_name, cfg, ip_count, vhost_count, r->filename, r->pool);

        return HTTP_SERVICE_UNAVAILABLE;

    } else if (vhost_count > cfg->vhost_limit) {
        vlimitconn_debug_log_buf = apr_psprintf(r->pool
            , "Rejected, too many connections to the vhost(%s) by VlimitConnVhost[limit=(%d) docroot=(%s)]."
            , header_name
            , cfg->vhost_limit
            , cfg->full_path
        );
        VLIMITCONN_DEBUG_SYSLOG("vlimitconn_check_limit: ", vlimitconn_debug_log_buf, r->pool);

        vlimitconn_logging("RESULT: 503", address, header_name, cfg, ip_count, vhost_count, r->filename, r->pool);

        return HTTP_SERVICE_UNAVAILABLE;

    } else {
        VLIMITCONN_DEBUG_SYSLOG("vlimitconn_check_limit: ", "OK: Passed all checks", r->pool);

        vlimitconn_logging("RESULT:  OK", address, header_name, cfg, ip_count, vhost_count, r->filename, r->pool);

        return DECLINED;

    }
}


/* ------------------------------------------------- */
/* --- Analyze from the Path to RealPath Routine --- */
/* ------------------------------------------------- */
static char *
realpath_for_fs(const char *path, char *resolved_path, int maxreslth, apr_pool_t *p) {

    int readlinks = 0;
    int n;

    char *npath;
    char link_path[PATH_MAX+1];
    char *buf;

    buf = apr_pcalloc(p, sizeof(char *));
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

        /* symlink analyzed */
        *npath = '\0';
        n = readlink(resolved_path, link_path, PATH_MAX);
        if (n < 0) {
            /* EINVAL means the file exists but isn't a symlink. */
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
            newbuf = apr_pcalloc(p, m + n + 1);
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


/* ----------------------------------------- */
/* --- Access Checker for Per Dir Config --- */
/* ----------------------------------------- */
/* Normal handler. This function is invoked to handle vlimitconnip directives within a per-directory context. */
static int vlimitconn_handler(request_rec *r)
{
    /* get configuration information */
    vlimitconn_config *cfg =
        (vlimitconn_config *) ap_get_module_config(r->per_dir_config, &vlimitconn_module);

    int result;
    char *real_path_dir = (char *)apr_pcalloc(r->pool, sizeof(char *) * PATH_MAX + 1);

    vlimitconn_debug_log_buf = apr_psprintf(r->pool
        , "cfg->ip_limit=(%d) cfg->vhost_limit=(%d) cfg->full_path=(%s)"
        , cfg->ip_limit
        , cfg->vhost_limit
        , cfg->full_path
    );
    VLIMITCONN_DEBUG_SYSLOG("vlimitconn_handler: ", vlimitconn_debug_log_buf, r->pool);

    /* full_path check */
    if (cfg->full_path != NULL) {
        if (realpath_for_fs(ap_document_root(r), real_path_dir, PATH_MAX, r->pool) == NULL) {
            vlimitconn_debug_log_buf = apr_psprintf(r->pool
                , "realpath_for_fs was failed. path=(%s)"
                , ap_document_root(r)
            );
            VLIMITCONN_DEBUG_SYSLOG("vlimitconn_handler: ", vlimitconn_debug_log_buf, r->pool);
            return DECLINED;
        }

        if (strcmp(cfg->full_path, real_path_dir) != 0) {

            vlimitconn_debug_log_buf = apr_psprintf(r->pool
                , "full_path not match cfg->full_path=(%s) <=> real_path_dir=(%s)"
                , cfg->full_path
                , real_path_dir     
            );
            VLIMITCONN_DEBUG_SYSLOG("vlimitconn_handler: ", vlimitconn_debug_log_buf, r->pool);
            VLIMITCONN_DEBUG_SYSLOG("vlimitconn_handler: ", "full_path not match end...", r->pool);

            return DECLINED;
        }

        vlimitconn_debug_log_buf = apr_psprintf(r->pool
            , "full_path match cfg->full_path=(%s) <=> real_path_dir=(%s)"
            , cfg->full_path
            , real_path_dir     
        );
        VLIMITCONN_DEBUG_SYSLOG("vlimitconn_handler: ", vlimitconn_debug_log_buf, r->pool);
    } else {
        vlimitconn_debug_log_buf = apr_psprintf(r->pool
            , "full_path not found. cfg->full_path=(%s)"
            , cfg->full_path
        );
        VLIMITCONN_DEBUG_SYSLOG("vlimitconn_handler: ", vlimitconn_debug_log_buf, r->pool);
    }

    VLIMITCONN_DEBUG_SYSLOG("vlimitconn_handler: ", "Entering normal handler", r->pool);
    result = vlimitconn_check_limit(r, cfg);
    VLIMITCONN_DEBUG_SYSLOG("vlimitconn_handler: ", "Exiting normal handler", r->pool);

    return result;
}


/* -------------------------------------------- */
/* --- Access Checker for Per Server Config --- */
/* -------------------------------------------- */
/* For server configration */
static int vlimitconn_quick_handler(request_rec *r, int lookup)
{
    /* get configuration information */
    vlimitconn_config *cfg = (vlimitconn_config *)
      ap_get_module_config(r->server->module_config, &vlimitconn_module);

    int result;
    char *real_path_dir = (char *)apr_pcalloc(r->pool, sizeof(char *) * PATH_MAX + 1);

    /* full_path check */
    if (cfg->full_path != NULL) {

        if (realpath_for_fs(ap_document_root(r), real_path_dir, PATH_MAX, r->pool) == NULL) {
            vlimitconn_debug_log_buf = apr_psprintf(r->pool
                , "realpath_for_fs was failed. path=(%s)"
                , ap_document_root(r)
            );
            VLIMITCONN_DEBUG_SYSLOG("vlimitconn_quick_handler: ", vlimitconn_debug_log_buf, r->pool);

            return DECLINED;
        }

        if (strcmp(cfg->full_path, real_path_dir) != 0) {

            vlimitconn_debug_log_buf = apr_psprintf(r->pool
                , "full_path not match cfg->full_path=(%s) <=> real_path_dir=(%s)"
                , cfg->full_path
                , real_path_dir     
            );
            VLIMITCONN_DEBUG_SYSLOG("vlimitconn_quick_handler: ", vlimitconn_debug_log_buf, r->pool);
            VLIMITCONN_DEBUG_SYSLOG("vlimitconn_quick_handler: ", "mod_vlimitconn: vlimitconn_quick_handler: full_path not match end...", r->pool);

            return DECLINED;
        }

        vlimitconn_debug_log_buf = apr_psprintf(r->pool
            , "full_path match cfg->full_path=(%s) <=> real_path_dir=(%s)"
            , cfg->full_path
            , real_path_dir     
        );
        VLIMITCONN_DEBUG_SYSLOG("vlimitconn_quick_handler: ", vlimitconn_debug_log_buf, r->pool);
    }

    VLIMITCONN_DEBUG_SYSLOG("vlimitconn_quick_handler: ", "mod_vlimitconn: Entering quick handler", r->pool);
    result = vlimitconn_check_limit(r, cfg);
    VLIMITCONN_DEBUG_SYSLOG("vlimitconn_quick_handler: ", "mod_vlimitconn: Entering quick handler", r->pool);

    return result;
}


/* ------------------------------------ */
/* --- Command_rec for VlimitConnIP--- */
/* ------------------------------------ */
/* Parse the VlimitConnIP directive */
static const char *set_vlimitconnip(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg_opt1)
{
    vlimitconn_config *cfg  = (vlimitconn_config *) mconfig;
    vlimitconn_config *scfg = 
        (vlimitconn_config *) ap_get_module_config(parms->server->module_config, &vlimitconn_module);

    signed long int limit = strtol(arg1, (char **) NULL, 10);

    /* No reasonable person would want more than 2^16. Better would be
       to use LONG_MAX but that causes portability problems on win32 */
    if( (limit > 65535) || (limit < 0) )
    {
        return "Integer overflow or invalid number";
    }

    if (parms->path != NULL) {
        /* Per-directory context */
        cfg->type      = SET_VLIMITCONNIP;
        cfg->ip_limit     = limit;
        cfg->full_path = apr_pstrdup(parms->pool, arg_opt1);
    } else {
        /* Per-server context */
        scfg->type      = SET_VLIMITCONNIP;
        scfg->ip_limit     = limit;
        scfg->full_path = apr_pstrdup(parms->pool, arg_opt1);
    }

    return NULL;
}


/* --------------------------------------- */
/* --- Command_rec for VlimitConnVhost--- */
/* --------------------------------------- */
/* Parse the VlimitConnVhost directive */
static const char *set_vlimitconnvhost(cmd_parms *parms, void *mconfig, const char *arg1, const char *arg_opt1)
{
    vlimitconn_config *cfg  = (vlimitconn_config *) mconfig;
    vlimitconn_config *scfg = 
        (vlimitconn_config *) ap_get_module_config(parms->server->module_config, &vlimitconn_module);

    signed long int limit = strtol(arg1, (char **) NULL, 10);

    /* No reasonable person would want more than 2^16. Better would be
       to use LONG_MAX but that causes portability problems on win32 */
    if( (limit > 65535) || (limit < 0) )
    {
        return "Integer overflow or invalid number";
    }

    if (parms->path != NULL) {
        /* Per-directory context */
        cfg->type        = SET_VLIMITCONNVHOST;
        cfg->vhost_limit = limit;
        cfg->full_path   = apr_pstrdup(parms->pool, arg_opt1);
    } else {
        /* Per-server context */
        scfg->type        = SET_VLIMITCONNVHOST;
        scfg->vhost_limit = limit;
        scfg->full_path   = apr_pstrdup(parms->pool, arg_opt1);
    }

    return NULL;
}


/* ------------------------ */
/* --- Command_rec Array--- */
/* ------------------------ */
static command_rec vlimitconn_cmds[] = {
    AP_INIT_TAKE12("VlimitConnIP", set_vlimitconnip, NULL, OR_LIMIT|RSRC_CONF, "maximum connections per IP address to DocumentRoot"),
    AP_INIT_TAKE12("VlimitConnVhost", set_vlimitconnvhost, NULL, OR_LIMIT|RSRC_CONF, "maximum connections per Vhost"),
    {NULL},
};


/* ------------------------------------------- */
/* --- Init Routine or ap_hook_post_config --- */
/* ------------------------------------------- */
/* Set up startup-time initialization */
static int vlimitconn_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
//    ap_log_error(APLOG_MARK, APLOG_MOD, 0, s, MODULE_NAME " " MODULE_VERSION " started.");
    VLIMITCONN_DEBUG_SYSLOG("vlimitconn_quick_handler: ", MODULE_NAME " " MODULE_VERSION " started.", p);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &vlimitconn_thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &vlimitconn_server_limit);

    if(apr_file_open(&vlimitconn_log_fp, VLIMITCONN_LOG_FILE, APR_WRITE|APR_APPEND|APR_CREATE,
           APR_OS_DEFAULT, p) != APR_SUCCESS){
        return OK;
    }

    return OK;
}


/* ---------------------- */
/* --- Register_hooks --- */
/* ---------------------- */
static void vlimitconn_register_hooks(apr_pool_t *p)
{
    static const char * const after_me[] = { "mod_cache.c", NULL };

    ap_hook_post_config(vlimitconn_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_quick_handler(vlimitconn_quick_handler, NULL, after_me, APR_HOOK_FIRST);
    ap_hook_access_checker(vlimitconn_handler, NULL, NULL, APR_HOOK_MIDDLE);
}


/* ------------------------------ */
/* --- Module Functions Array --- */
/* ------------------------------ */
module AP_MODULE_DECLARE_DATA vlimitconn_module = {
    STANDARD20_MODULE_STUFF,
    vlimitconn_create_dir_config,        /* create per-dir config structures     */
    NULL,                                 /* merge  per-dir    config structures  */
    vlimitconn_create_server_config,     /* create per-server config structures  */
    NULL,                                 /* merge  per-server config structures  */
    vlimitconn_cmds,                     /* table of config file commands        */
    vlimitconn_register_hooks
};
