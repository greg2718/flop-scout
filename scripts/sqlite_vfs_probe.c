/* Diagnostic-only VFS shim. Loaded with ctypes ONLY by the copy benchmark.
 * Delegates every operation unchanged; no SQL, payload, or paths are logged. */
#include <sqlite3.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
static sqlite3_vfs *base; static sqlite3_vfs shim;
typedef struct {sqlite3_file file; sqlite3_file *real; int kind; double checkpoint_begin;} File;
static double stats[2][6][4];
static pthread_mutex_t mu=PTHREAD_MUTEX_INITIALIZER;
static int crash_after=-1;
void scout_probe_crash_after(int n){crash_after=n;}
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}
static void add(File*f,int op,double t,int bytes){double d=now()-t;pthread_mutex_lock(&mu);double *s=stats[f->kind][op];s[0]++;s[1]+=d;if(d>s[2])s[2]=d;s[3]+=bytes;pthread_mutex_unlock(&mu);}
#define F File*f=(File*)p
#define M f->real->pMethods
static int closef(sqlite3_file*p){F;return M->xClose(f->real);}
static int readf(sqlite3_file*p,void*b,int n,sqlite3_int64 o){F;double t=now();int r=M->xRead(f->real,b,n,o);add(f,0,t,n);return r;}
static int writef(sqlite3_file*p,const void*b,int n,sqlite3_int64 o){F;if(!f->kind && crash_after>0 && --crash_after==0)_exit(23);double t=now();int r=M->xWrite(f->real,b,n,o);add(f,1,t,n);return r;}
static int syncf(sqlite3_file*p,int flags){F;double t=now();int r=M->xSync(f->real,flags);add(f,2,t,0);return r;}
static int truncatef(sqlite3_file*p,sqlite3_int64 n){F;double t=now();int r=M->xTruncate(f->real,n);add(f,3,t,0);return r;}
static int sizef(sqlite3_file*p,sqlite3_int64*n){F;return M->xFileSize(f->real,n);}
static int lockfile(sqlite3_file*p,int n){F;return M->xLock(f->real,n);}
static int unlockfile(sqlite3_file*p,int n){F;return M->xUnlock(f->real,n);}
static int reservedf(sqlite3_file*p,int*n){F;return M->xCheckReservedLock(f->real,n);}
static int controlf(sqlite3_file*p,int n,void*a){F;double t=now();if(n==SQLITE_FCNTL_CKPT_START)f->checkpoint_begin=t;if(n==SQLITE_FCNTL_CKPT_DONE && f->checkpoint_begin){add(f,5,f->checkpoint_begin,0);f->checkpoint_begin=0;}int r=M->xFileControl(f->real,n,a);add(f,4,t,0);return r;}
static int sectorf(sqlite3_file*p){F;return M->xSectorSize(f->real);}
static int devicef(sqlite3_file*p){F;return M->xDeviceCharacteristics(f->real);}
static int mapf(sqlite3_file*p,int a,int b,int c,void volatile**d){F;return M->xShmMap(f->real,a,b,c,d);}
static int shmlockfile(sqlite3_file*p,int a,int b,int c){F;return M->xShmLock(f->real,a,b,c);}
static void barrierf(sqlite3_file*p){F;M->xShmBarrier(f->real);}
static int unmapf(sqlite3_file*p,int n){F;return M->xShmUnmap(f->real,n);}
static int fetchf(sqlite3_file*p,sqlite3_int64 a,int b,void**c){F;if(M->iVersion<3||!M->xFetch){*c=0;return SQLITE_OK;}return M->xFetch(f->real,a,b,c);}
static int unfetchf(sqlite3_file*p,sqlite3_int64 a,void*b){F;return M->iVersion>=3&&M->xUnfetch?M->xUnfetch(f->real,a,b):SQLITE_OK;}
static const sqlite3_io_methods methods={3,closef,readf,writef,truncatef,syncf,sizef,lockfile,unlockfile,reservedf,controlf,sectorf,devicef,mapf,shmlockfile,barrierf,unmapf,fetchf,unfetchf};
static int openf(sqlite3_vfs*v,const char*z,sqlite3_file*p,int flags,int*out){F;memset(f,0,sizeof(*f));f->real=(sqlite3_file*)((char*)p+sizeof(File));f->kind=!!(flags&SQLITE_OPEN_WAL);int r=base->xOpen(base,z,f->real,flags,out);if(r==SQLITE_OK)f->file.pMethods=&methods;return r;}
int scout_probe_init(void){base=sqlite3_vfs_find(0);shim=*base;shim.zName="scout-probe";shim.szOsFile=sizeof(File)+base->szOsFile;shim.xOpen=openf;return sqlite3_vfs_register(&shim,1);}
double scout_probe_value(int kind,int op,int field){pthread_mutex_lock(&mu);double v=stats[kind][op][field];pthread_mutex_unlock(&mu);return v;}
void scout_probe_reset(void){memset(stats,0,sizeof(stats));}
