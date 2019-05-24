#include <stdio.h>

int main(){

    int i = 0;	
	for(i=0; i<20; i++) {
		printf("%02d. (i>>3) = %d , ((i&0x07)<<5) = %d \n",i,(i>>3), ((i&0x07)<<5));
		//printf("%02d. (i>>4) = %d , ((i&0x0F)<<4) = %d \n",i,(i>>4), ((i&0x0F)<<4));
		//printf("%02d. (i>>2) = %d , ((i&0x0F)<<6) = %d \n",i,(i>>2), ((i&0x03)<<6));
	}
	
	printf("\n\n===========================\n\n");
	system("pause");	
}
