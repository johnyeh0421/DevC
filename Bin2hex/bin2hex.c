#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <malloc.h> 
#include <direct.h>

struct ch_block{
	struct ch_block* next;
	char num;		
};

int main(){
	
	FILE *fp,*fdatap,*fdataout,*file;
	char ch,data_ch;
	char name_str[50] = "Null";
	char bin_name_str[40];
	char buf[50][50];	
	char tmp_buf[50];
	char str[6];
	int i = 0,j = 0,k = 0,ii = 0,jj=0,tail_cnt = 0;
	char cnt =0;
	char ctrl_f = 0;
	char row_size = 16;
	struct ch_block *current;
	struct ch_block *start = (struct ch_block*)malloc(sizeof(struct ch_block));
	system("dir/b>>DeleteMe.~");
	file = mkdir(".bin");

	fp = fopen("DeleteMe.~","rb");
	while(!feof(fp))
	{
		fgets(name_str,50,fp);
		strcpy(buf[cnt],name_str);
		cnt++;			
	}
	for(k=0;k<(cnt-1);k++){	
    ctrl_f = 0;
		for(i=0;i<strlen(buf[k]);i++){
		  if(((buf[k][i])==46)){
				if(((buf[k][i+1])=='t')&&((buf[k][i+2])=='x')&&((buf[k][i+3])=='t')&&((buf[k][i+4])==13)){               
					buf[k][i+4] = 0;
					//printf("%s\n",buf[k]);
					ctrl_f = 1;
				}
				else if(((buf[k][i+1])=='h')&&((buf[k][i+2])=='t')&&((buf[k][i+3])=='m')&&((buf[k][i+4])=='l')&&((buf[k][i+5])==13)){
					buf[k][i+5] = 0;
					//printf("%s\n",buf[k]);
					ctrl_f = 1;
				}
				else if(((buf[k][i+1])=='g')&&((buf[k][i+2])=='i')&&((buf[k][i+3])=='f')&&((buf[k][i+4])==13)){
					buf[k][i+4] = 0;
					//printf("%s\n",buf[k]);
					ctrl_f = 1;
				}
				else if(((buf[k][i+1])=='c')&&((buf[k][i+2])=='s')&&((buf[k][i+3])=='s')&&((buf[k][i+4])==13)){
					buf[k][i+4] = 0;
					//printf("%s\n",buf[k]);
					ctrl_f = 1;
				}
		  }              
		}
    if(ctrl_f==1){                      
      //printf("ctrl_buf = %s\n",buf[k]);
      strcpy(tmp_buf,buf[k]);
      //printf("tmp_buf = %c\n",tmp_buf[2]);
      fdatap = fopen(buf[k],"rb");
      for(ii=0;(tmp_buf[ii]!='.')&&(ii<strlen(tmp_buf));ii++);
      tmp_buf[ii]=0;
      sprintf(bin_name_str,".bin\\%s.bin",tmp_buf);
      printf("bin_name = %s\n",bin_name_str);
      //printf("tmp_buf = %s\n",tmp_buf);
      fdataout = fopen(bin_name_str,"wb");
      current = start;
      while(1){
	      data_ch = fgetc(fdatap);
	      //printf("%c",data_ch);
	      if(feof(fdatap)){
					current->next = NULL;
					current = start;	 
					break;
				}
				current->num = data_ch;	
				current->next = (struct ch_block*)malloc(sizeof(struct ch_block));
				current = current->next;	
      }
      fputc('{', fdataout);
      fputc('\n', fdataout);
    	for(jj = 0,tail_cnt = 0;current->next!=NULL;current = current->next,jj++,tail_cnt++){			
  			if(!(jj%row_size) && jj!=0){
  				fputc('\n', fdataout);				
  			} 
				sprintf(str,"0x%02x, " , (current->num)&0xff);
  			for(j=0;j<6;j++){
  			   fputc(*(str+j) , fdataout);
  			}
			}
     	if(!(tail_cnt%16)){
     		fputc('\n', fdataout);
     	}
			fputc('0', fdataout);
			fputc('\n', fdataout);
			fputc('}', fdataout);
			fclose(fdatap);
			fclose(fdataout);               
  	}
	}
	fclose(fp);

	system("del /Q DeleteMe.~");	
	system("pause");
	return 0;
}

