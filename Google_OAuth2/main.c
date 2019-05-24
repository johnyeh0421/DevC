#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winsock.h>
#include <malloc.h> 
#include <direct.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "main.h"

#define CLIENT_ID 		"90185992096-0rq2oep8evmv6qil9l7cc3otvaph8cl7.apps.googleusercontent.com"
#define CLIENT_SCRECT 	"*****"

#define EEP_EMAIL_SEND_TO_ADDR			0
#define EEP_EMAIL_SEND_SUBJECT_ADDR		50
#define EEP_EMAIL_SEND_CONTENT_ADDR		100

const char index_html[] = 		"index.html";
const char oauthcallback_html[] = "oauthcallback?";
const char update_html[] = 		"update.html";
const char send_gmail_html[] = 		"send_gmail.cgi";
char *start_ptr,*end_ptr;

void readHtmlData(SOCKET client_sockfd, char* fname){
	FILE *fdatap,*fout;
	char ofilename[100];
	int len = 0;
	size_t ret;
	send(client_sockfd, "HTTP/1.1 200 OK\r\n\r\n", strlen("HTTP/1.1 200 OK\r\n\r\n"), 0);

	sprintf(ofilename,"WebPages/%s",fname);
	fdatap = fopen(ofilename,"rb");
	do{
		memset(readfiletmp , 0 , sizeof(readfiletmp));
		memset(writebuf, 0 , sizeof(writebuf));
		ret = fread(readfiletmp, 1, 1024, fdatap);
		counti = 0; 
		countj = 0;
		len = check_send_len(RESPONSE_HTML);
		send(client_sockfd, writebuf, len, 0);
	}
	while(ret>0);
	fclose(fdatap);
}

int main() {

	SOCKET server_sockfd, client_sockfd;
	int server_len, client_len;
	struct sockaddr_in server_address;
	struct sockaddr_in client_address;

	// 註冊 Winsock DLL
	WSADATA wsadata;
	if(WSAStartup(0x101,(LPWSADATA)&wsadata) != 0) {
		printf("Winsock Error\n");
		exit(1);                                         
	}

	// 產生 server socket
	server_sockfd = socket(AF_INET, SOCK_STREAM, 0); // AF_INET(使用IPv4); SOCK_STREAM; 0(使用預設通訊協定，即TCP)
	if(server_sockfd == SOCKET_ERROR) {
		printf("Socket Error\n");
		exit(1);
	}

	char input_ip[20];
	char input_port[20];

	sprintf(input_ip,"127.0.0.1");
	sprintf(input_port,"100");
	printf("\n\n請於瀏覽器上輸入 : \"http://localhost:100/\" 取得Google Oauth2.0授權 !!!\n\n");
	
	server_address.sin_family = AF_INET;					//AF_INT(使用IPv4)
	server_address.sin_addr.s_addr = inet_addr(input_ip);		//IP根據電腦網卡進行設定，電腦目前是192.168.1.7，因此server IP就必須是192.168.1.7 
	server_address.sin_port = htons(atoi(input_port));		//設定埠號 atoi 字串轉 int
	server_len = sizeof(server_address);


	if(bind(server_sockfd, (struct sockaddr *)&server_address, server_len) < 0) {
		printf("Bind Error\n");
		exit(1);
	}

	if(listen(server_sockfd, 5) < 0) {
		printf("Listen Error\n");
		exit(1);
	}

	memset(&Email_Info, 0, sizeof(s_Email_Info));
	EEPROM_BufferRead(EEP_EMAIL_SEND_TO_ADDR, Email_Info.sned_to, EMAIL_STRING_LEN);
	EEPROM_BufferRead(EEP_EMAIL_SEND_SUBJECT_ADDR, Email_Info.sned_subject, EMAIL_STRING_LEN);
	EEPROM_BufferRead(EEP_EMAIL_SEND_CONTENT_ADDR, Email_Info.send_content, EMAIL_STRING_LEN);
	printf("EEPROM .sned_to = %s\n", Email_Info.sned_to);
	printf("EEPROM .sned_subject = %s\n", Email_Info.sned_subject);
	printf("EEPROM .send_content = %s\n", Email_Info.send_content);

	/*======================*/
	sprintf(g_client_id, "%s", CLIENT_ID);
	sprintf(g_client_screct, "%s", CLIENT_SCRECT);
	/*======================*/
	unsigned char tick = 0, switch_task_tick = 0; 
	while(1) {

		tick = ((tick+1)%MAX_TICK_CNT);
		switch_task_tick = (tick%SWITCH_ROUTINE_TICK_CNT); 

		switch(switch_task_tick) {
				case 0: 
					//printf("Server waiting...\n");
					client_len = sizeof(client_address);

					client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_address, &client_len);
					if(client_sockfd == SOCKET_ERROR) {
						printf("Accept Error\n");
						exit(1);
					}
					memset(readbuf,0,READ_MAX_LEN);
					recv(client_sockfd, readbuf, READ_MAX_LEN, 0);
					//printf("%s\n",readbuf);
					char *GET_ptr = strstr(readbuf , "GET /");
					char *HTTP_ptr = strstr(readbuf , "HTTP");
					if(HTTP_ptr){
						readbuf[HTTP_ptr-GET_ptr-1] = 0;
					}
					if(GET_ptr && HTTP_ptr){
						if(!strcmp(readbuf, "GET /")){
							printf("\n\n請按下Authorize按鈕 !!!\n\n");
							get_info = INDEX_HTML;
							memset(&Oauth_info , 0 , sizeof(Oauth_info));
							readHtmlData(client_sockfd,(char*)index_html);
							g_oauth_status = 0;
						}
						else if(strstr(readbuf, oauthcallback_html)){
							get_info = OAUTHCALLBACK_HTML;
							memset(&Oauth_info , 0 , sizeof(Oauth_info));
							if(start_ptr = strstr(readbuf,"code=")){
								sprintf(Oauth_info.authorization_code,"%s",start_ptr+strlen("code="));
								SetBit(g_oauth_status, OAUTH_AUTHORIZATION_CODE);
							}
							readHtmlData(client_sockfd,(char*)index_html);
						}
						else if(strstr(readbuf, update_html)){
							get_info = UPDATE_HTML;
							memset(g_send_buf , 0 , sizeof(g_send_buf));
							sprintf(g_send_buf, "HTTP/1.1 200 OK\r\n\r\n%s",Oauth_info.user_email);
							send(client_sockfd, g_send_buf, strlen(g_send_buf), 0);

						}
						else if(strstr(readbuf, send_gmail_html)){
							get_info = INDEX_HTML;
							//printf("readbuf = %s\n", readbuf);
							memset(&Email_Info, 0, sizeof(s_Email_Info));
							get_string_form_cgi(readbuf, Email_Info.sned_to, "send_to=", "&send_subject=", EMAIL_STRING_LEN);
							get_string_form_cgi(readbuf, Email_Info.sned_subject, "send_subject=", "&send_content=", EMAIL_STRING_LEN);
							get_string_form_cgi(readbuf, Email_Info.send_content, "send_content=", "&cgiend", EMAIL_STRING_LEN);
							printf("Email_Info.sned_to=%s\n", Email_Info.sned_to);
							printf("Email_Info.sned_subject=%s\n", Email_Info.sned_subject);
							printf("Email_Info.send_content=%s\n", Email_Info.send_content);
							EEPROM_BufferWrite(EEP_EMAIL_SEND_TO_ADDR, Email_Info.sned_to, EMAIL_STRING_LEN);
							EEPROM_BufferWrite(EEP_EMAIL_SEND_SUBJECT_ADDR, Email_Info.sned_subject, EMAIL_STRING_LEN);
							EEPROM_BufferWrite(EEP_EMAIL_SEND_CONTENT_ADDR, Email_Info.send_content, EMAIL_STRING_LEN);							
							readHtmlData(client_sockfd,(char*)index_html);
							SetBit(g_oauth_status, OAUTH_SEND_EMAIL);
						}
						closesocket(client_sockfd);
					}
					break;
				case 1: 
					if(ValBit(g_oauth_status, OAUTH_AUTHORIZATION_CODE)){
						memset(g_body_buf,0,sizeof(g_body_buf));
						memset(g_send_buf,0,sizeof(g_send_buf));
						
						sprintf(g_body_buf,"client_id=%s&client_secret=%s&code=%s&redirect_uri=%s%s/oauthcallback&grant_type=authorization_code", g_client_id, g_client_screct, Oauth_info.authorization_code,"http://","localhost:100");
						sprintf(g_send_buf,"POST /o/oauth2/token HTTP/1.1\r\nHost:accounts.google.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length:%d\r\n\r\n%s",strlen(g_body_buf),g_body_buf);
						do_oauth("accounts.google.com");
						if(pickupJsonItem(g_recv_buf,Oauth_info.access_token,"access_token")){
							SetBit(g_oauth_status, OAUTH_ACCESS_TOKEN);
						}
						if(pickupJsonItem(g_recv_buf,Oauth_info.refresh_token,"refresh_token")){
							SetBit(g_oauth_status, OAUTH_REFRESH_TOKEN);
						}
						
						memset(g_send_buf,0,sizeof(g_send_buf));
						memset(g_recv_buf,0,sizeof(g_recv_buf));
						sprintf(g_send_buf,"GET /oauth2/v2/userinfo HTTP/1.1\r\nHost:www.googleapis.com\r\nAuthorization:Bearer %s\r\n\r\n",Oauth_info.access_token);
						do_oauth("www.googleapis.com");
						memset(Oauth_info.user_email,0,sizeof(Oauth_info.user_email));
						if(pickupJsonItem(g_recv_buf,Oauth_info.user_email,"email")){
							SetBit(g_oauth_status, OAUTH_USER_EMAIL);
						}

						printf("\n ============================== \n\n");
						printf("Authorization Code(%d):\n%s\n",strlen(Oauth_info.authorization_code), Oauth_info.authorization_code);
						printf("\nAccess Token(%d) = \n%s\n",strlen(Oauth_info.access_token), Oauth_info.access_token);
						printf("\n\nRefresh Token(%d) = \n%s\n\n",strlen(Oauth_info.refresh_token), Oauth_info.refresh_token);
						printf("\nUser_Email(%d) = \n%s\n",strlen(Oauth_info.user_email), Oauth_info.user_email);
						printf("\n\n ============================== \n");						
						ClrBit(g_oauth_status, OAUTH_AUTHORIZATION_CODE);

					}
					break;
				case 2:
					if(ValBit(g_oauth_status, OAUTH_SEND_EMAIL)){
						printf("\n ============================== \n\n");
						printf("Send EMAIL");
						printf("\n\n ============================== \n");
						memset(g_body_buf,0,sizeof(g_body_buf));
						memset(g_send_buf,0,sizeof(g_send_buf));
						/*
						From: John Doe <despond421@gmail.com> 
						To: Mary Smith <despond421@gmail.com> 
						Subject: Hello 
						Date: Fri, 21 Nov 1997 09:55:06 -0600 

						This is a message just to say hello. So, "Hello".
						*/
						int offset_len = 0;
						offset_len += sprintf(g_body_buf+offset_len ,"From: John Yeh <%s>\r\n", Oauth_info.user_email);
						offset_len += sprintf(g_body_buf+offset_len ,"To: John Yeh <%s>\r\n", Email_Info.sned_to);
						offset_len += sprintf(g_body_buf+offset_len ,"Subject: %s\r\n\r\n", Email_Info.sned_subject);
						offset_len += sprintf(g_body_buf+offset_len ,"%s\r\n", Email_Info.send_content);
						int send_offset_len = 0;
						send_offset_len += sprintf(g_send_buf+send_offset_len, "POST /upload/gmail/v1/users/%s/messages/send HTTP/1.1\r\n", Oauth_info.user_email);
						send_offset_len += sprintf(g_send_buf+send_offset_len, "Content-Type: message/rfc822\r\n");
						send_offset_len += sprintf(g_send_buf+send_offset_len, "Authorization: Bearer %s\r\n", Oauth_info.access_token);
						send_offset_len += sprintf(g_send_buf+send_offset_len, "Accept: */*\r\n");
						send_offset_len += sprintf(g_send_buf+send_offset_len, "Host: www.googleapis.com\r\n");
						send_offset_len += sprintf(g_send_buf+send_offset_len, "Content-Length: %d\r\n", strlen(g_body_buf));
						send_offset_len += sprintf(g_send_buf+send_offset_len, "Connection: keep-alive\r\n\r\n");
						send_offset_len += sprintf(g_send_buf+send_offset_len, "%s", g_body_buf);						
						
						if(do_oauth("www.googleapis.com")){
							printf("\n===========\n");
							printf("g_recv_buf:\n%s\n", g_recv_buf);
							printf("\n===========\n");
						}
						ClrBit(g_oauth_status, OAUTH_SEND_EMAIL);
					}
					break;
		}
		sleep(100);
	}
	
	system("Pause");
}

