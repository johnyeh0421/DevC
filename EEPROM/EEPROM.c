#include <stdio.h>
#include <malloc.h> 

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

int main(){
    
	#define BUFFER_LEN 16
	char write_buf[BUFFER_LEN+1];
	char read_buf[BUFFER_LEN+1];

	memset(write_buf, 0 , sizeof(write_buf));    
	sprintf(write_buf, "0123456789ABCDEFG");
	EEPROM_BufferWrite(0, write_buf, BUFFER_LEN);

	sprintf(write_buf, "5678");
	EEPROM_BufferWrite(16, write_buf, BUFFER_LEN);

	sprintf(write_buf, "aaaaa");
	EEPROM_BufferWrite(32, write_buf, BUFFER_LEN);


	memset(read_buf, 0 , sizeof(read_buf));
	EEPROM_BufferRead(0, read_buf, BUFFER_LEN);
	printf("read_buf1 = %s\n", read_buf);

	memset(read_buf, 0 , sizeof(read_buf));
	EEPROM_BufferRead(16, read_buf, BUFFER_LEN);
	printf("read_buf2 = %s\n", read_buf);

	memset(read_buf, 0 , sizeof(read_buf));
	EEPROM_BufferRead(32, read_buf, BUFFER_LEN);
	printf("read_buf3 = %s\n", read_buf);

	system("pause");
	return 0;    
}
