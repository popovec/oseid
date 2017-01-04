#include <stdio.h>
#include <signal.h>
#include <setjmp.h>

sigjmp_buf JumpBuffer;
void INThandler (int);

void
INThandler (int sig)
{
  signal (sig, INThandler);
  printf ("CTRL-C, card reset (type 'quit' to exit)\n");
  siglongjmp (JumpBuffer, 1);
}
