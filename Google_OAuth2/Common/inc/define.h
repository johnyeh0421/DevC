#ifndef DEFINE_H
#define DEFINE_H    

#define WRITE_MAX_LEN	2048
#define READ_MAX_LEN	8192

#define MAX_TICK_CNT					4
#define SWITCH_ROUTINE_TICK_CNT	4

#define SWITCH_NOT_RETURN			0xFFFFFFFF
#define MAX_SEND_LEN				(2048)


#define SetBit(VAR,Place)	( VAR |= (1<<(Place)) )
#define ClrBit(VAR,Place)	( VAR &= ((1<<(Place))^0xFFFFFFFF) )
#define ValBit(VAR,Place)	(VAR & (1<<(Place)))


#endif /* DEFINE_H */
