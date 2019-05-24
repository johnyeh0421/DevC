#include <stdio.h>

typedef struct
{
   unsigned char       AA;
   unsigned short       A;
   unsigned short       B;
   unsigned int         C;
   unsigned int         H; 
}Test_Type;

typedef union
{
   unsigned int    D;
   unsigned short  E;
   
}Test_Union;



void main(){
     
	Test_Type test;
	Test_Union test2;
	
	
	printf("Size of test = %d\n",sizeof(test));
	printf("Size of test.AA = %d\n",sizeof(test.AA));
	printf("Size of test.A = %d\n",sizeof(test.A));
	printf("Size of test.B = %d\n",sizeof(test.B));
	printf("Size of test.C = %d\n",sizeof(test.C));
	printf("Size of test.H = %d\n",sizeof(test.H));
	
	printf("Adress test.AA = %x\n",&(test.AA));
	printf("Adress test.A = %x\n",&(test.A));
	printf("Adress test.B = %x\n",&(test.B));
	printf("Adress test.C = %x\n",&(test.C));
	printf("Adress test.H = %x\n",&(test.H));
	
	printf("Size of test2 = %d\n",sizeof(test2));
	printf("Size of test2.D = %d\n",sizeof(test2.D));
	printf("Size of test2.E= %d\n",sizeof(test2.E));
	
	unsigned char a=0;
	a = -1;
	printf("a = %u\n", a);
	
	
	printf("\n===============\n");
	system("pause");     
}
