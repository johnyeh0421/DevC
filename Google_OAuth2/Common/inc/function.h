

#ifndef FUNCTION_H_
#define FUNCTION_H_

#include "Variable.h"
#include "define.h"

void EEPROM_BufferWrite(int addr, char* pBuffer, int len);
void EEPROM_BufferRead(int addr, char* pBuffer, int len);
char* memmem(char* str , int len , char* cmp);
extern int fs_fix_byte(char *dest,const char *source, int count);
extern int fs_switch_com(char *dest, char *source , e_socket_response_t idx, char *b, unsigned int max_send_len);
extern int fs_loadfixfile(char *dest, char *source , e_socket_response_t idx, WORD max_send_len);
extern int check_send_len(e_socket_response_t idx);
int get_string_form_cgi(char* in_str, char* out_str, char* start_str, char* end_str, int max_len);
extern char pickupJsonItem(char* in_str,char* out_str, char* cmp_str);
int oauth_tls_init(void);
char oauth_create_comm(int *fd, char *host);
extern char do_oauth(char *host);

#endif  //FUNCTION_H_
