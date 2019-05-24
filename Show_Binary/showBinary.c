#include <stdio.h>

#define SetBit(VAR,Place)	( VAR |= (1<<(Place)) )
#define ClrBit(VAR,Place)	( VAR &= ((1<<(Place))^0xFFFFFFFF) )
#define ValBit(VAR,Place)	(VAR & (1<<(Place)))

void showBinary(int val){
	int i;
	for(i=15;i>=0;i--){
		if(ValBit(val, i)){
			printf("1");			
		}
		else{
			printf("0");						
		}
		if(!(i%4)){
			printf(" ");								
		}	
	}
	printf("\n");	
}


short a = 11;
short b = 65;
short c,d;

void main(){
	
	printf("a = ");
	showBinary(a);
						
	printf("b = ");
	showBinary(b);		
	
	printf("a|b = ");
	c = a|b;
	showBinary(c);
	
	printf("a^b = ");
	d = a^b;
	showBinary(d);
		
	printf("\n=============\n");
	system("pause");	
}
