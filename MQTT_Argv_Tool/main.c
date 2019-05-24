#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

#include <signal.h>
#include <memory.h>
#include <sys/time.h>
#include <limits.h>

#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_interface.h"
#include "aws_iot_config.h"

char	g_mqtt_rx[AWS_IOT_MQTT_RX_BUF_LEN];
char	g_mqtt_rx_topic[100];

int sub_time;
int systime;
int err_time;
time_t rawtime;
struct tm * timeinfo;

int MQTTcallbackHandler(MQTTCallbackParams params) {

	if((int)params.MessageParams.PayloadLen > AWS_IOT_MQTT_RX_BUF_LEN)
		return 0;

	time (&rawtime);
	timeinfo = localtime (&rawtime);
	sub_time = time(NULL);

//	timeinfo.tm_sec    = 10;
//	timeinfo.tm_min    = 10;
//	timeinfo.tm_hour   = 6;
//	timeinfo.tm_mday   = 25;
//	timeinfo.tm_mon    = 2;
//	timeinfo.tm_year   = 89;
//	timeinfo.tm_wday   = 6;

	memcpy(g_mqtt_rx_topic, params.pTopicName, (int)params.TopicNameLen);
	memcpy(g_mqtt_rx, (char*)params.MessageParams.pPayload, (int)params.MessageParams.PayloadLen);
	g_mqtt_rx[(int)params.MessageParams.PayloadLen] = '\0';

	printf("Subscribe callback (%s) >> %s\n", g_mqtt_rx_topic, asctime(timeinfo));
	printf("%s\n", g_mqtt_rx);
	printf("=============================================\n\n");

	return 0;
}

void disconnectCallbackHandler(void) {
	WARN("MQTT Disconnect");
}

typedef enum{ 
	EMQ_CONNECT_STAGE,
	EMQ_PUB_SUB_STAGE,
	EMQ_DISCONNECT_STAGE
}e_Mqtt_Cloud_Stage;

e_Mqtt_Cloud_Stage g_mqtt_cloud_stage = EMQ_CONNECT_STAGE;
static char mqtt_client_id[100];
static char mqtt_publish_topic[128];
static char mqtt_subscribe_topic[128];
char cPayload[256];
char do_pub_flag = 0;
int test_cnt = 0;

char mqtt_host_name[128];
int mqtt_port;
char mqtt_login_account[128];
char mqtt_login_password[128];

void main(int argc, char** argv) {
	IoT_Error_t rc = NONE_ERROR;
	
/*========================================================*/
/*================ Get Argv infomation ==========================*/

	//	printf ("argc = %d\n", argc);
	// pub/sub topic payload
	if(argc == 4){
		if(strstr(*++argv, "pub")){
			sprintf(mqtt_publish_topic, "%s", *++argv);
			sprintf(cPayload, "%s", *++argv);
			do_pub_flag = 1;
		}
		else if(strstr(*argv, "sub")){
			sprintf(mqtt_subscribe_topic, "%s", *++argv);
		}		
		else{
			printf ("[0x00] Error input parameter (%d)\n", argc-1);
			sleep(2000);
			return;
		}
	}
	else{
		printf ("[0x01] Error input parameter (%d)\n", argc-1);
		sleep(2000);
		return;
	}
	
/*================ END - Get Argv infomation =====================*/
/*========================================================*/
#if 0
//	if(do_pub_flag){
//		printf("publish\n");
//		printf("mqtt_publish_topic = %s\n", mqtt_publish_topic);
//		printf("cPayload = %s\n", cPayload);
//	}
//	else{
//		printf("subscribe\n");
//		printf("mqtt_subscribe_topic = %s\n", mqtt_subscribe_topic);
//	}
//	return;

//	do_pub_flag = 1;
//	sprintf(mqtt_publish_topic, "$aws/things/11F_Projector/shadow/update");
//	sprintf(mqtt_subscribe_topic, "$aws/things/11F_Projector/shadow/update");
//	sprintf(cPayload, "{\"state\":{\"reported\":{\"aaa\":\"%d\"}}}", (unsigned)time(NULL));
	
	
#endif
/*========================================================*/
/*================== Get mqtt connect infomation=================*/

	FILE *sys_cfg;
	char name_str[128];
	int len;
	int row_cnt = 0;
	sys_cfg = fopen("./MqttCloudParam.cfg","rb");
	memset(mqtt_host_name, 0, sizeof(mqtt_host_name));
	memset(mqtt_login_account, 0, sizeof(mqtt_login_account));
	memset(mqtt_login_password, 0, sizeof(mqtt_login_password));
	
	while(!feof(sys_cfg))
	{
		memset(name_str, 0, sizeof(name_str));
		fgets(name_str,128,sys_cfg);
		name_str[strlen(name_str)-2] = 0;
		len = strlen(name_str);
		//printf("%d. %s\n", len, name_str);
		if(row_cnt == 0){
			if(len)
				memcpy(mqtt_host_name, name_str, len);
			else{
				printf ("[0x02] Error SysParam.cfg\n");
				sleep(2000);
				return;
			}
		}
		if(row_cnt == 1){
			if(len)
				mqtt_port = atoi(name_str);
			else{
				printf ("[0x03] Error SysParam.cfg\n");
				sleep(2000);
				return;
			}
		}
		else if(row_cnt == 2 && len){
			memcpy(mqtt_login_account, name_str, len);
		}
		else if(row_cnt == 3 && len){
			memcpy(mqtt_login_password, name_str, len);
		}
		row_cnt++;
	}
	
	// debug
	printf("mqtt_publish_topic = %s\n", mqtt_publish_topic);
	printf("mqtt_subscribe_topic = %s\n", mqtt_subscribe_topic);
	printf("mqtt_host_name = %s\n", mqtt_host_name);
	printf("mqtt_port = %d\n", mqtt_port);
	printf("mqtt_login_account = %s\n", mqtt_login_account);
	printf("mqtt_login_password = %s\n", mqtt_login_password);
	printf("cPayload = %s\n", cPayload);
	sleep(2000);
	
/*==================END - Get mqtt connect infomation=============*/
/*========================================================*/

	sprintf(mqtt_client_id, "%d", (unsigned)time(NULL));

	MQTTConnectParams connectParams = MQTTConnectParamsDefault;
	connectParams.KeepAliveInterval_sec = 35;
	connectParams.isCleansession = true;
	connectParams.MQTTVersion = MQTT_3_1_1;
	connectParams.pClientID = mqtt_client_id;
	connectParams.pHostURL = mqtt_host_name;
	connectParams.port = mqtt_port;
	connectParams.pUserName = mqtt_login_account;
	connectParams.pPassword = mqtt_login_password;
	connectParams.isWillMsgPresent = false;
	connectParams.pRootCALocation = ROOT_CA_FILENAME;
	connectParams.pDeviceCertLocation = CERTIFICATE_FILENAME;
	connectParams.pDevicePrivateKeyLocation = PRIVATE_KEY_FILENAME;
	connectParams.mqttCommandTimeout_ms = 12000;
	connectParams.tlsHandshakeTimeout_ms = 20000;
	connectParams.isSSLHostnameVerify = false;// ensure this is set to true for production
	connectParams.disconnectHandler = disconnectCallbackHandler;
	
	MQTTSubscribeParams subParams = MQTTSubscribeParamsDefault;
	subParams.mHandler = MQTTcallbackHandler;
	subParams.pTopic = mqtt_subscribe_topic;
	subParams.qos = QOS_0;
	
	MQTTMessageParams Msg= MQTTMessageParamsDefault;
	Msg.qos = QOS_0;
	Msg.pPayload = (void *)cPayload;
	
	MQTTPublishParams Params= MQTTPublishParamsDefault;
	Params.pTopic = mqtt_publish_topic;
	
	while(1){
		switch(g_mqtt_cloud_stage){
				case EMQ_CONNECT_STAGE:
					//INFO("Connecting...");
					printf("Connecting... Topic : %s\n", (do_pub_flag)?mqtt_publish_topic:mqtt_subscribe_topic);
					rc = aws_iot_mqtt_connect(&connectParams);
					if (NONE_ERROR != rc) {
						ERROR("Error(%d) connecting to %s:%d", rc, connectParams.pHostURL, connectParams.port);
					}
					if(NONE_ERROR == rc) {
						if(do_pub_flag){
							g_mqtt_cloud_stage = EMQ_PUB_SUB_STAGE;
						}
						else{
							INFO("Start Subscribing...");
							rc = aws_iot_mqtt_subscribe(&subParams);
							if (NONE_ERROR != rc) {
								ERROR("Error subscribing");
							}
							else{
								g_mqtt_cloud_stage = EMQ_PUB_SUB_STAGE;
							}
						}
					}
					break;
				case EMQ_PUB_SUB_STAGE:
					rc = aws_iot_mqtt_yield(100);
					systime =  time(NULL);
					if((sub_time) && (systime > sub_time)){
						err_time = systime - sub_time;						
						if(err_time>90){
//							printf("sub_time > %d\n", sub_time);
//							printf("systime > %d\n", systime);
//							printf("err_time > %d\n\n", err_time);							
							time (&rawtime);
							timeinfo = localtime (&rawtime);
							printf(".........no response > %s\n", asctime(timeinfo));
							sub_time =  time(NULL);
						}
					}
					
					if(do_pub_flag){
						Msg.PayloadLen = strlen(cPayload) + 1;
						Params.MessageParams = Msg;
						rc = aws_iot_mqtt_publish(&Params);
						printf("publish >> %s\n", cPayload);
						printf("Ok\n");
						sleep(2000);
						return;
					}
					if(NONE_ERROR != rc){
						g_mqtt_cloud_stage = EMQ_CONNECT_STAGE;
						ERROR("An error occurred in the loop.\n");
					}
					break;
				default:
					g_mqtt_cloud_stage = EMQ_CONNECT_STAGE;
					break;
		}
		sleep(10);
	}
	return;
}

