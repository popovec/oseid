while (sigsetjmp (JumpBuffer, 1));
signal (SIGINT, INThandler);
