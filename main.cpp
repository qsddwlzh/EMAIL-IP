#include "openssl/bio.h"  
#include "openssl/ssl.h"  
#include "openssl/err.h"  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <ctime>
#include <ifaddrs.h>
#include<fstream>
SSL_METHOD  *meth;
SSL_CTX     *ctx;
SSL_CTX     *ctx_READ;
SSL         *ssl;
SSL	    *ssl_READ;
int nFd;
int nFd_R;
//char szBuffer[1024];
char R_Buffer[10000];
char W_Buffer[10000];
char U_C_name[100] = {"xxxxxxx.com"};//你要向那个电子邮箱发送IP地址
char U_name[100] = {"xxxxxx.com"};//此程序要登录哪个电子邮箱
char U_password[100] = {"xxxxxxxxxx"};//此程序登录的电子邮箱的密码
char *base64_encode(char *str) ;
void EXIT_IF_TRUE (bool x){
        if (x){
            do {
                    fprintf(stderr, "check '%d' is true\n",x);
                    exit(2);
            }while(0);
        }
}
struct sockaddr_in Write_remote_addr;
struct sockaddr_in remote_addr;
bool Init_ssl(){
	SSLeay_add_ssl_algorithms();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ERR_load_BIO_strings();
}
bool SendEmailInit(){
	memset(R_Buffer,'\0',10000);
	memset(&remote_addr,0,sizeof(remote_addr)); //清零
	remote_addr.sin_family=AF_INET; //设置为IP通信
	remote_addr.sin_addr.s_addr=inet_addr("220.181.15.161");//服务器IP地址	
	remote_addr.sin_port=htons(465); //服务器端口号
	EXIT_IF_TRUE((ctx = SSL_CTX_new (TLS_client_method())) == NULL);
	if((nFd=socket(PF_INET,SOCK_STREAM,0))<0)
	{
            std::cout << '[' << time(0) << ']' << "创建套接字失败" << std::endl;
    	    return 0;
	}
	if(connect(nFd,(struct sockaddr *)&remote_addr,sizeof(struct sockaddr))<0)
	{
		std::cout << '[' << time(0) << ']' << "连接服务器失败" << std::endl;
	        return 0;
	}
	EXIT_IF_TRUE( (ssl = SSL_new (ctx)) == NULL);
	SSL_set_fd (ssl, nFd);
	EXIT_IF_TRUE( SSL_connect (ssl) != 1);
	SSL_read(ssl,R_Buffer,BUFSIZ);
	SSL_write(ssl,"helo smtp",strlen("helo smtp"));
        SSL_write(ssl,"\r\n",strlen("\r\n"));
	SSL_read(ssl,R_Buffer,BUFSIZ);
	SSL_write(ssl,"auth login",strlen("auth login"));
	SSL_write(ssl,"\r\n",strlen("\r\n"));
	SSL_read(ssl,R_Buffer,BUFSIZ);
	SSL_write(ssl,base64_encode(U_name),strlen(base64_encode(U_name)));
        SSL_write(ssl,"\r\n",strlen("\r\n"));
	SSL_read(ssl,R_Buffer,BUFSIZ);
	SSL_write(ssl,base64_encode(U_password),strlen(base64_encode(U_password)));
        SSL_write(ssl,"\r\n",strlen("\r\n"));
	SSL_read(ssl,R_Buffer,BUFSIZ);
	std::cout << '[' << time(0) << ']' << "SMTP协议初始化完成或登录失败" << std::endl;
	std::cout << '[' << time(0) << ']' << "服务器返回信息:" << R_Buffer  << std::endl;
	return 1;
}
void SendEmails(char* data,char* to_Uname){
	memset(R_Buffer,'\0',10000);
	SSL_write(ssl,"mail from:<",strlen("mail from:<"));
	SSL_write(ssl,U_name,strlen(U_name));
        SSL_write(ssl,">\r\n",strlen(">\r\n"));
	SSL_write(ssl,"rcpt to:<",strlen("rcpt to:<"));
        SSL_write(ssl,to_Uname,strlen(to_Uname));
        SSL_write(ssl,">\r\n",strlen(">\r\n"));
	SSL_write(ssl,"data",strlen("data"));
	SSL_write(ssl,"\r\n",strlen("\r\n"));
	SSL_write(ssl,"subject:",strlen("subject:"));
	SSL_write(ssl,data,strlen(data));
	SSL_write(ssl,"\r\n.\r\n",strlen("\r\n.\r\n"));
	SSL_read(ssl,R_Buffer,BUFSIZ);
	std::cout << '[' << time(0) << ']' << "发送完成" << std::endl;
}
bool SendEmailClose(){
	SSL_free (ssl);
	SSL_CTX_free (ctx);
	close(nFd);
}
char *base64_encode(char *str)
{
    long len;
    long str_len;
    char *res;
    int i,j;
    char base64_table[100]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    str_len=strlen(str);
    if(str_len % 3 == 0)
        len=str_len/3*4;
    else
        len=(str_len/3+1)*4;
    res=(char*)(malloc(sizeof(unsigned char)*len+1));
    res[len]='\0';
    for(i=0,j=0;i<len-2;j+=3,i+=4)
    {
        res[i]=base64_table[str[j]>>2]; //取出第一个字符的前6位并找出对应的结果字符
        res[i+1]=base64_table[(str[j]&0x3)<<4 | (str[j+1]>>4)]; //将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符
        res[i+2]=base64_table[(str[j+1]&0xf)<<2 | (str[j+2]>>6)]; //将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符
        res[i+3]=base64_table[str[j+2]&0x3f]; //取出第三个字符的后6位并找出结果字符
    }

    switch(str_len % 3)
    {
        case 1:
            res[i-2]='=';
            res[i-1]='=';
            break;
        case 2:
            res[i-1]='=';
            break;
    }
    return res;
}
char addressBuffer[INET6_ADDRSTRLEN+20];
char addressBuffer_last[INET6_ADDRSTRLEN+20];
char a[10000];
int i3 = 0;
int main(){
	std::freopen("log.txt","w",stdout);
	Init_ssl();
	std::cout << '[' << time(0) << ']' << "SSL INIT OK" << std::endl;
	std::ifstream srcFile;
	while(1){
		srcFile = std::ifstream("/proc/net/ipv6_route", std::ios::in);//重新打开刷新
		for(int i = 0;i < strlen(addressBuffer);i++){
                        addressBuffer[i] = ' ';
                }
		srcFile.read(a,sizeof(a));
		for(int i = 0;i < strlen(a);i++){
                        if(a[i] == '\n'){i3++;}
                        if(i3 == 6){
                	        for(int k = 0;k < 32;k++){
                	                addressBuffer[k] = a[i+k+1];
        	                }
	                        break;
                        }
                }
                i3 = 0;
		if(strcmp(addressBuffer_last,addressBuffer)){
			std::cout << '[' << time(0) << ']' << "IP地址变化,现在为:" << addressBuffer << std::endl;
			if(SendEmailInit()){
				SendEmails(addressBuffer,U_C_name);
				SendEmailClose();
			}else{
				std::cout << '[' << time(0) << ']' << "SMTP初始化失败" << std::endl;
			}
		}
		strcpy(addressBuffer_last,addressBuffer);
		for(int delay_i = 0;delay_i < 2290000;delay_i++);//延时，为了不过于频繁读取IP文件
		srcFile.close();
	}
}
