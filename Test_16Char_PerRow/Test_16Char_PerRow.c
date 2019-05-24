#include <stdio.h>

char str[] = "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCD";
void main(){
     
	int i;
	for(i=0; i<strlen(str); i++){
		printf("%c", *(str+i)); 
		if(!((i+1)%16)){
			printf("\n");           
		}        
	}
	
	printf("\n===============\n");
	system("pause");     
}
