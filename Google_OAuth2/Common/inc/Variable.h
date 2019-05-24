#ifndef Variable_H
#define Variable_H

#include "define.h"

typedef enum{
	OAUTH_INIT_STATUS,
	OAUTH_AUTHORIZATION_CODE,
	OAUTH_ACCESS_TOKEN,
	OAUTH_REFRESH_TOKEN,
	OAUTH_REFRESH_ACCESS_TOKEN,
	OAUTH_USER_EMAIL,
	OAUTH_CONNECT_FAIL,
	OAUTH_REJECT,
	OAUTH_SEND_EMAIL
}OAUTH_STATUS_t;

typedef  enum {
	SEND_NONE,
	RESPONSE_HTML
}e_socket_response_t;

typedef  enum {
	HTML_NONE,
	INDEX_HTML,
	OAUTHCALLBACK_HTML,
	UPDATE_HTML,
	SEND_EMAIL_HTML
}e_get_html_t;

typedef struct{
	char authorization_code[500];
	char access_token[500];
	char refresh_token[256];
	char user_email[128];
	char gmail_sender_name[64];
	char gmail_enable;
}s_Oauth_Info;

#define EMAIL_STRING_LEN 50
typedef struct{
	char sned_from[EMAIL_STRING_LEN+1];
	char sned_to[EMAIL_STRING_LEN+1];
	char sned_subject[EMAIL_STRING_LEN+1];
	char send_content[EMAIL_STRING_LEN+1];
}s_Email_Info;


extern char 	writebuf[WRITE_MAX_LEN+1];
extern char	readbuf[READ_MAX_LEN+1];
extern char	g_body_buf[512];
extern char	g_send_buf[1024];
extern char	g_recv_buf[4096];
extern char	readfiletmp[1096];
extern char g_client_id[300];
extern char g_client_screct[300];

extern int				g_oauth_status;
extern int				counti; 
extern int 			countj;
extern int 			cont_tmp_len;
extern s_Oauth_Info	Oauth_info;
extern e_get_html_t	get_info;
extern s_Email_Info	Email_Info;

#endif /* __Variable_H */
