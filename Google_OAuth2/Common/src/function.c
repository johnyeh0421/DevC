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
#include "define.h"
#include "Variable.h"

#include "mbedtls/config.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

//#define MY_DEBUG
#ifdef MY_DEBUG
#define MY_DEBUG(...)    \
    {\
    printf("DEBUG:   %s L#%d ", __PRETTY_FUNCTION__, __LINE__);  \
    printf(__VA_ARGS__); \
    printf("\n"); \
    }
#else
#define MY_DEBUG(...)
#endif

struct ch_list{
	struct ch_list* next;
	char ch;
};

void EEPROM_BufferWrite(int addr, char* pBuffer, int len)
{
	FILE *pFile, *pRead;
	fpos_t position;
	int i = 0;
	int cnt = 0;
	struct ch_list* list_current;
	struct ch_list* list_start = (struct ch_list*)malloc(sizeof(struct ch_list));
	
	
	pRead = fopen("EEPROM/EEPROM.txt","rb");
	if( NULL == pRead ){
		printf( "Read open failure" );
	}
	else{
		list_current = list_start;
		while(1){
			char c = fgetc(pRead);
			if(feof(pRead)){
				list_current->next = NULL;
				break;
			}
			cnt ++;
			list_current->ch = c;
			list_current->next = (struct ch_list*)malloc(sizeof(struct ch_list));
			list_current = list_current->next;
		}
	}
	fclose(pRead);
	
	pFile = fopen("EEPROM/EEPROM.txt","wb");
	if( NULL == pFile ){
		printf( "Write open failure" );
	}
	else{
		for(list_current = list_start, i=0; list_current->next != NULL; list_current = list_current->next, i++){
			//printf("ch(%d) = %02X\n", i, list_current->ch);
			putc (list_current->ch , pFile);
		}
		fseek ( pFile , addr , SEEK_SET );
		for (i = 0 ; i < len ; i++) {
			putc (pBuffer[i] , pFile);
		}
		pBuffer[len-1] = 0;
		putc (pBuffer[i] , pFile);
	}
	fclose(pFile);
}

void EEPROM_BufferRead(int addr, char* pBuffer, int len)
{
	FILE *pFile;
	fpos_t position;
	int i = 0;
	
	pFile = fopen("EEPROM/EEPROM.txt","rb");
	
	if( NULL == pFile ){
		printf( "Read open failure" );
	}
	else{
		fgetpos (pFile, &position);
		position = addr;
		fsetpos (pFile, &position);
		for (i = 0 ; i < len ; i++) {
			pBuffer[i] = getc(pFile);
		}
	}
	fclose(pFile);
}

char* memmem(char* str , int len , char* cmp){
	int i;
	char* src = str;
	int size = strlen(cmp);
	while(1){
		src = memchr(src , *(cmp) , len);
		if(src != NULL){
			for(i=0;i<size;i++){
				if(*(src+i) == *(cmp+i))
					continue;
				else
					break;
			}
			if(i==size)
				return src;
			src++;
			
		}
		else
			return NULL;
	}
}

int fs_fix_byte(char *dest,const char *source, int count){
	
	int	k,m;
	k=0;
	m=0;

	loop:
        if(count+k>MAX_SEND_LEN+1)
            return k;
		if(source[m] == '\0' )
		    return k;
		else
			dest[k++]=source[m++];
	goto loop;
}

int fs_switch_com(char *dest, char *source , e_socket_response_t idx, char *b, unsigned int max_send_len){
	
	#define tx_string_byte(x) 			 countj+=fs_fix_byte(dest+countj,(const char *)x, countj)
	char show_str[256];
	memset(show_str , 0 , sizeof(show_str));

	switch(idx) {

		case RESPONSE_HTML:
			switch(*b) {
				case '0':
					switch(*(b+1)) {
						case '0':
							if(ValBit(g_oauth_status, OAUTH_USER_EMAIL)){
								tx_string_byte(Oauth_info.user_email);
							}
							else{
								tx_string_byte("");
							}
							break;
						case '1':
							if(get_info == INDEX_HTML){
								tx_string_byte("Authorize");
							}
							else{
								tx_string_byte("Change");
							}
							break;
						case '2':
							if(get_info == OAUTHCALLBACK_HTML){
								tx_string_byte("g_5s();");
							}
							else{
								tx_string_byte("");
							}
							break;
						case '3':
							tx_string_byte(g_client_id);
							break;
					}
					break;
				case '1':
					switch(*(b+1)) {
						case '0':
							tx_string_byte(Email_Info.sned_to);
							break;
						case '1':
							tx_string_byte(Email_Info.sned_subject);
							break;
						case '2':
							tx_string_byte(Email_Info.send_content);
							break;
					}
					break;
			}
			break;
	}

	if(countj >= max_send_len) {
		countj = cont_tmp_len;
		return (counti - 2);
	}
	return SWITCH_NOT_RETURN;
}

int fs_loadfixfile(char *dest, char *source , e_socket_response_t idx, WORD max_send_len) {
	
	int fs_switch_return;
	char b[4];

	loop:
	
	if(countj >= max_send_len || source[counti] == 0) {
		dest[countj] = '\0';
		return counti; 
	}
	
	if(source[counti] != '@') {
		dest[countj] = source[counti]; 
		cont_tmp_len=countj;
		++countj; 
	}
	else{ 
		if(source[counti] == '@') {
				if(source[counti + 1] == 0 || source[counti + 2] == 0) {
					dest[countj] = '\0'; 
					return counti;
				}
				cont_tmp_len=countj;
				b[0]=source[++counti];
				b[1]=source[++counti];
				b[2]=0;
				fs_switch_return = fs_switch_com(dest, source, idx, b, max_send_len);
		}
		if(fs_switch_return != SWITCH_NOT_RETURN) {
			counti = fs_switch_return ;
			dest[countj] = '\0'; 
			return fs_switch_return;
		}	
	}
		
	++counti;	
	goto loop;
}

int check_send_len(e_socket_response_t idx){

	switch(idx){

		case RESPONSE_HTML:
			fs_loadfixfile(writebuf , (char*)readfiletmp , RESPONSE_HTML , MAX_SEND_LEN);
			return strlen(writebuf);
			break;
		default:
			return 0;
			break;
	}
}

int get_string_form_cgi(char* in_str, char* out_str, char* start_str, char* end_str, int max_len){

	char * start_ptr = strstr(in_str, start_str);
	char * end_ptr = strstr(in_str, end_str);
	if(start_ptr && end_ptr){
		//printf("start_ptr=%s\n", start_ptr);
		//printf("end_ptr=%s\n", end_ptr);
		start_ptr+= strlen(start_str);
		int cpy_len = end_ptr - start_ptr;
		//printf("start_ptr=%s\n", start_ptr);
		//printf("cpy_len=%d\n", cpy_len);
		if(cpy_len<max_len && cpy_len>=0){
			memcpy(out_str, start_ptr, cpy_len);
			return 1;
		}
		else{
			return 0;
		}
	}
	else{
		return 0;
	}
}


char pickupJsonItem(char* in_str,char* out_str, char* cmp_str){

	char *ptr;
	char start_flag = 0;
	int i=0,j=0;

	memset(out_str , 0 , sizeof(out_str));
	if(ptr = strstr(in_str,cmp_str)){
		for(i=0;i<strlen(ptr);i++){
			if(*(ptr+i)=='"'&&start_flag){
				break;
			}
			if(*(ptr+i-3)==':'&&*(ptr+i-2)==' '&&*(ptr+i-1)=='"'){
				start_flag=1;
			}
			if(start_flag){
				out_str[j++]=*(ptr+i);		
			}
		}
		return 1;
	}
	return 0;	
}

/*=====================Oauth 2.0============================*/
/*========================================================*/
static mbedtls_entropy_context oauth_entropy;
static mbedtls_ctr_drbg_context oauth_ctr_drbg;
static mbedtls_ssl_context oauth_ssl;
static mbedtls_ssl_config oauth_conf;
static mbedtls_x509_crt oauth_cacert;
static mbedtls_net_context oauth_server_fd;

int oauth_tls_init() {
	int ret;
	const char *pers = "google_test";
	unsigned char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
	
	mbedtls_net_init(&oauth_server_fd);
	mbedtls_ssl_init(&oauth_ssl);
	mbedtls_ssl_config_init(&oauth_conf);
	mbedtls_ctr_drbg_init(&oauth_ctr_drbg);
	mbedtls_x509_crt_init(&oauth_cacert);

	MY_DEBUG("\n  . Seeding the random number generator...");
	mbedtls_entropy_init(&oauth_entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&oauth_ctr_drbg, mbedtls_entropy_func, &oauth_entropy, (const unsigned char *) pers,
			strlen(pers))) != 0) {
		MY_DEBUG(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
		return ret;
	} MY_DEBUG("ok\n");

	return ret;
}

char oauth_create_comm(int *fd, char *host){

	int ret;	

	oauth_tls_init();
	
	if ((ret = mbedtls_net_connect(&oauth_server_fd, host, "443", MBEDTLS_NET_PROTO_TCP)) != 0) {
		MY_DEBUG(" failed\n  ! mbedtls_net_connect returned -0x%x\n\n", -ret);
		return ret;
	}

	MY_DEBUG("  . Setting up the SSL/TLS structure...");
	if ((ret = mbedtls_ssl_config_defaults(&oauth_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		MY_DEBUG(" failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret);
		return ret;
	}


	mbedtls_ssl_conf_authmode(&oauth_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

	mbedtls_ssl_conf_rng(&oauth_conf, mbedtls_ctr_drbg_random, &oauth_ctr_drbg);

	mbedtls_ssl_conf_read_timeout(&oauth_conf, 5000);

	if ((ret = mbedtls_ssl_setup(&oauth_ssl, &oauth_conf)) != 0) {
		MY_DEBUG(" failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret);
		return ret;
	}
	if ((ret = mbedtls_ssl_set_hostname(&oauth_ssl, host)) != 0) {
		MY_DEBUG(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
		return ret;
	}
	mbedtls_ssl_set_bio(&oauth_ssl, &oauth_server_fd, mbedtls_net_send, NULL, mbedtls_net_recv_timeout);
	MY_DEBUG(" ok\n");

	mbedtls_ssl_conf_ca_chain(&oauth_conf, &oauth_cacert, NULL);

	MY_DEBUG("  . Performing the SSL/TLS handshake...");
	while ((ret = mbedtls_ssl_handshake(&oauth_ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			MY_DEBUG(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
			if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
				MY_DEBUG("    Unable to verify the server's certificate. "
						"Either it is invalid,\n"
						"    or you didn't set ca_file or ca_path "
						"to an appropriate value.\n"
						"    Alternatively, you may want to use "
						"auth_mode=optional for testing purposes.\n");
			}
			return ret;
		}
	}

	MY_DEBUG(" ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n", mbedtls_ssl_get_version(&oauth_ssl), mbedtls_ssl_get_ciphersuite(&oauth_ssl));
	
	return ret;

	
}

void oauth_close_comm(int fd){
	mbedtls_ssl_free(&oauth_ssl);
	close(fd);
}
char do_oauth(char *host){
	int fd;
	struct timeval timeout;
	fd_set fds;
	timeout.tv_sec = 100;
	timeout.tv_usec = 0;
	int tmp_ret=0;

	if(oauth_create_comm(&fd,host)){
		oauth_close_comm(&fd);
		return 0;		
	}
	memset(g_recv_buf , 0 , sizeof(g_recv_buf));
	mbedtls_ssl_write( &oauth_ssl, (unsigned char const*)g_send_buf, strlen(g_send_buf) );
	printf("g_send_buf(%d):\n%s\n", strlen(g_send_buf), g_send_buf);

	FD_ZERO(&fds);
	FD_SET(fd , &fds);
	select(fd+1 , &fds , NULL , NULL , &timeout);

	if (FD_ISSET(fd, &fds)){
		tmp_ret = mbedtls_ssl_read( &oauth_ssl, (char*)g_recv_buf, 4096);
		if(tmp_ret>0){
			tmp_ret += mbedtls_ssl_read(&oauth_ssl, (char*)g_recv_buf+tmp_ret, 4096-tmp_ret);		
		}
	}
	else{
		printf("Receive Timed Out.\n");
		oauth_close_comm(fd);
		return 0;	
	}
	oauth_close_comm(&fd);
	return 1;		
}

/*=================END -Oauth 2.0============================*/
/*========================================================*/


