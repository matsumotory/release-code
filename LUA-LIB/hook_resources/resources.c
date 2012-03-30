#include <stdio.h>
#include <malloc.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <syslog.h>

#include "apr.h"
#include "apr_general.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_pools.h"

#define INITIAL_VALUE              0

char *fs_debug_rchecker_log_buf = NULL;

typedef struct rusage_resouce_data {

    double cpu_utime;
    double cpu_stime;
    double shared_mem;

} RESOURCE_DATA;

void RCHECKER_DEBUG_SYSLOG(const char *key, const char *msg, apr_pool_t *p)
{   
    char *fs_buf = NULL;

    fs_buf = (char *)apr_psprintf(p,"%s%s", key, msg);

    openlog(NULL, LOG_PID, LOG_SYSLOG);
    syslog(LOG_DEBUG, fs_buf);
    closelog();
}


static double get_time_from_rutime(time_t sec, suseconds_t usec)
{
    return sec + (double)usec * 1e-6;
}


static double get_resource(const char *type, const char *member)
{
    struct rusage *resources;
    struct rusage *resources_s;
    struct rusage *resources_c;

    apr_pool_t *p;
    apr_initialize();
    apr_pool_create(&p, NULL);
    
    RESOURCE_DATA *pAnalysisResouce;
    pAnalysisResouce = (RESOURCE_DATA *)apr_pcalloc(p, sizeof(RESOURCE_DATA));
    resources = (struct rusage *)apr_pcalloc(p, sizeof(struct rusage));

#ifdef __MOD_DEBUG__
    RCHECKER_DEBUG_SYSLOG("_get_rusage_resource: ", "start", p);
#endif

    if (strcmp(type, "SELF") == 0) {
        if (getrusage(RUSAGE_SELF ,resources) == -1) {
            pAnalysisResouce->cpu_utime = INITIAL_VALUE;
            pAnalysisResouce->cpu_stime = INITIAL_VALUE;
            return -1;
        }   
    } else if (strcmp(type, "CHILD") == 0) {
        if (getrusage(RUSAGE_CHILDREN ,resources) == -1) {
            pAnalysisResouce->cpu_utime = INITIAL_VALUE; 
            pAnalysisResouce->cpu_stime = INITIAL_VALUE;
            return -1;
        }   
    } else if (strcmp(type, "ALL") == 0) {
        resources_s = (struct rusage *)apr_pcalloc(p, sizeof(struct rusage));
        resources_c = (struct rusage *)apr_pcalloc(p, sizeof(struct rusage));
        if (getrusage(RUSAGE_SELF ,resources_s) == -1) {
            pAnalysisResouce->cpu_utime = INITIAL_VALUE;
            pAnalysisResouce->cpu_stime = INITIAL_VALUE;
            return -1;
        }   
        if (getrusage(RUSAGE_CHILDREN ,resources_c) == -1) {
            pAnalysisResouce->cpu_utime = INITIAL_VALUE;
            pAnalysisResouce->cpu_stime = INITIAL_VALUE;
            return -1;
        }   
        resources->ru_utime.tv_sec  = resources_s->ru_utime.tv_sec + resources_c->ru_utime.tv_sec;
        resources->ru_utime.tv_usec = resources_s->ru_utime.tv_usec + resources_c->ru_utime.tv_usec;
        resources->ru_stime.tv_sec  = resources_s->ru_stime.tv_sec + resources_c->ru_stime.tv_sec;
        resources->ru_stime.tv_usec = resources_s->ru_stime.tv_usec + resources_c->ru_stime.tv_usec;
        resources->ru_minflt        = resources_s->ru_minflt + resources_c->ru_minflt;
    }   

    pAnalysisResouce->cpu_utime  = get_time_from_rutime(resources->ru_utime.tv_sec, resources->ru_utime.tv_usec);
    pAnalysisResouce->cpu_stime  = get_time_from_rutime(resources->ru_stime.tv_sec, resources->ru_stime.tv_usec);
    pAnalysisResouce->shared_mem = (((double)resources->ru_minflt * (double)getpagesize() / 1024 / 1024));

#ifdef __MOD_DEBUG__
    fs_debug_rchecker_log_buf = apr_psprintf(p,
            "type=(%s) ru_utime=(%lf) ru_stime=(%lf) ru_utime.tv_sec=(%ld) ru_utime.tv_usec=(%ld) ru_stime.tv_sec=(%ld) ru_stime.tv_usec=(%ld) ru_ixrss=(%ld) ru_idrss=(%ld) ru_isrss=(%ld) ru_minflt=(%ld) ru_majflt=(%ld) ru_nswap=(%ld) ru_inblock=(%ld) ru_oublock=(%ld) ru_msgsnd=(%ld) ru_msgrcv=(%ld) ru_nsignals=(%ld) ru_nvcsw=(%ld) ru_nivcsw=(%ld) getpagesize=(%d)"
            , type
            , pAnalysisResouce->cpu_utime
            , pAnalysisResouce->cpu_stime
            , resources->ru_utime.tv_sec 
            , resources->ru_utime.tv_usec
            , resources->ru_stime.tv_sec
            , resources->ru_stime.tv_usec
            , resources->ru_ixrss
            , resources->ru_idrss
            , resources->ru_isrss
            , resources->ru_minflt
            , resources->ru_majflt
            , resources->ru_nswap
            , resources->ru_inblock
            , resources->ru_oublock
            , resources->ru_msgsnd
            , resources->ru_msgrcv
            , resources->ru_nsignals
            , resources->ru_nvcsw
            , resources->ru_nivcsw
            , getpagesize()
    );      
    RCHECKER_DEBUG_SYSLOG("_get_rusage_resource: ", fs_debug_rchecker_log_buf, p);
#endif  
    
#ifdef __MOD_DEBUG__
    RCHECKER_DEBUG_SYSLOG("_get_rusage_resource: ", "end", p);
#endif      

    apr_pool_destroy(p);
    apr_terminate();
            
    if (strcmp(member, "cpu_utime") == 0) {
        return pAnalysisResouce->cpu_utime;
    } else if (strcmp(member, "cpu_stime") == 0) {
        return pAnalysisResouce->cpu_stime;
    } else if (strcmp(member, "shared_mem") == 0) {
        return pAnalysisResouce->shared_mem;
    }       
            
    return -1;
}       


static int l_get_resource(lua_State *L)
{
    const char *type, *member;
    double result;

    type = lua_tostring(L, 1);
    member = lua_tostring(L, 2);

    result = get_resource(type, member);
    lua_pushnumber(L, result);
    return 1;
}

static const struct luaL_reg resourceslib[] = {
    {"get", l_get_resource},
    {NULL, NULL},
};

int luaopen_resources(lua_State *L)
{
    luaL_register (L, "resources", resourceslib);
    return 1;
}
