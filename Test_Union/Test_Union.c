#include <stdio.h>



union unionType
{
    float b;
    //unsigned char a[4];
    unsigned short a[2];
};

int main(void)
{
    union unionType u;
    //u.b = 221.820007;
    //u.b = 230.309998;
    u.a[0] = 0x4000;
    u.a[1] = 0x4366;

    printf("sizeof=%d\n", sizeof(u));
    printf("u.b = %f\n", u.b);
    printf("u.a[0] = %02X\n", u.a[0]);
    printf("u.a[1] = %02X\n", u.a[1]);
    printf("u.a[0]d = %d\n", u.a[0]);
    printf("u.a[1]d = %d\n", u.a[1]);
    //printf("u.a[2] = %02X\n", u.a[2]);
    //printf("u.a[3] = %02X\n", u.a[3]);

    printf("\n=============\n");    
    u.b = 221.270004;
    printf("sizeof=%d\n", sizeof(u));
    printf("u.b = %f\n", u.b);
    printf("u.a[0] = %02X\n", u.a[0]);
    printf("u.a[1] = %02X\n", u.a[1]);
    
    printf("\n=============\n");
    u.b = 222.779999;
    printf("sizeof=%d\n", sizeof(u));
    printf("u.b = %f\n", u.b);
    printf("u.a[0] = %02X\n", u.a[0]);
    printf("u.a[1] = %02X\n", u.a[1]);
    
    //printf("u.a[2] = %02X\n", u.a[2]);
    //printf("u.a[2] = %02X\n", u.a[3]);
    system("pause"); 
}
