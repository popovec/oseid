
// signalize reader state
// WAIT = reader wait for command from host
// BUSY = reader toggles LED (waiting wor card, null byt sending)
// RUN  = command parsing/response generating


#if 1
// led is on on idle, of on run
#define LED1_INIT()  PORTA.PIN6CTRL = PORT_OPC_TOTEM_gc; PORTA.DIRSET = PIN6_bm
#define LED1_IDLE()  PORTA.OUTSET = PIN6_bm
#define LED1_BUSY()  PORTA.OUTTGL = PIN6_bm
#define LED1_RUN()   PORTA.OUTCLR = PIN6_bm
#define LED1_OFF()   PORTA.OUTCLR = PIN6_bm
#else
#define LED1_INIT()
#define LED1_IDLE()
#define LED1_BUSY()
#define LED1_RUN()
#define LED1_OFF()
#endif

// signalize suspend/online
#if 1
#define LED2_INIT()  PORTA.PIN5CTRL = PORT_OPC_TOTEM_gc; PORTA.DIRSET = PIN5_bm
#define LED2_RUN()   PORTA.OUTSET = PIN5_bm
#define LED2_SUSPEND()   PORTA.OUTCLR = PIN5_bm
#else
#define LED2_INIT()
#define LED2_SUSPEND()
#define LED2_RUN()
#endif
