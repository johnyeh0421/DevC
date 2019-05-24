#include "Variable.h"



char writebuf[WRITE_MAX_LEN+1];
char readbuf[READ_MAX_LEN+1];
char	g_body_buf[512];
char	g_send_buf[1024];
char	g_recv_buf[4096];
char readfiletmp[1096];
char g_client_id[300];
char g_client_screct[300];

int			g_oauth_status;
int			counti; 
int 			countj;
int 			cont_tmp_len;
s_Oauth_Info	Oauth_info;
e_get_html_t	get_info;
s_Email_Info	Email_Info;


