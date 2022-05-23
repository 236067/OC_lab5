#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>           // close()
#include <fcntl.h>

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h> 
#include <error.h>
#include <assert.h>

#define MAX_BUF		100000 


typedef enum _Cmd
{
	GetEmp,
	SetEmp,
	Stop
}
Cmd;


int rd = 0, wr = 0;
char recvbuf[MAX_BUF];
char sendbuf[MAX_BUF];


int get_int(char**p)
{
	int res = *(int*)*p;
	*p += sizeof(int);
	return res;
}


void get_str(char**p, char* buf)
{
	int len = *(int*)*p;
	*p += sizeof(int);
	memcpy(buf, *p, len);
	*p += len;
	buf[len] = 0;
}


void set_int(char**p, int value)
{
	*(int*)*p = value;
	*p += sizeof(int);
}


void set_str(char**p, char* buf)
{
	int len = strlen(buf);
	*(int*)*p = len;
	*p += sizeof(int);
	memcpy(*p, buf, len);
	*p += len;
}
	

int recvn(int sock, char* buf, int n)
{
	int len = 0;
	while(len < n) {
		int ret = read(sock, buf + len, n - len);
		if(ret <= 0) return ret;
		len += ret;
	}
	return len;
}


void S(char* buf, int len)
{
	int ret = write(wr, buf, len);
	if(ret < 0) {
		printf("send failed: %s\n", strerror(errno));
		exit(-1);
	}
	if(ret == 0) {
		printf("disconnected from server\n");
		exit(-1);
	}
}


char* R(char* buf)
{
	int ret = recvn(rd, recvbuf, sizeof(int));
	if(ret < 0) {
		printf("recv failed: %s\n", strerror(errno));
		exit(-1);
	}
	if(ret == 0) {
		printf("disconnected from server\n");
		exit(-1);
	}
	
	int len = *(int*)recvbuf - sizeof(int);
	ret = recvn(rd, recvbuf, len);
	if(ret < 0) {
		printf("recv failed: %s\n", strerror(errno));
		exit(-1);
	}
	if(ret == 0) {
		printf("disconnected from server\n");
		exit(-1);
	}
	return recvbuf;
}


int op_getemp(int id, int w)
{
	char* p = sendbuf;
	set_int(&p, 0);
	set_int(&p, GetEmp);
	set_int(&p, id);
	set_int(&p, w);
	*(int*)sendbuf = p - sendbuf;
	S(sendbuf, p - sendbuf);
	
	printf("command GETEMP sent\n");
	
	p = R(recvbuf);
	int res = get_int(&p);
	printf("server response received\n");
	
	if(res == 0) {
		char name[100];
		get_str(&p, name);
		char hours[100];
		get_str(&p, hours);
		
		
		printf("name: %s\n", name);
		printf("hours: %s\n", hours);
	}
	else {
		printf("not found\n");
	}
	return res == 0 ? 1 : 0;
}


int op_setemp(int id, char* name, char* hours)
{
	char* p = sendbuf;
	set_int(&p, 0);
	set_int(&p, SetEmp);
	set_int(&p, id);
	set_str(&p, name);
	set_str(&p, hours);
	*(int*)sendbuf = p - sendbuf;
	S(sendbuf, p - sendbuf);
	
	printf("command SETEMP sent\n");
	
	p = R(recvbuf);
	int res = get_int(&p);
	printf("server response received\n");
	
	if(res == 0) {
		printf("updated\n");
	}
	else {
		printf("not found\n");
	}
	return res == 0 ? 1 : 0;
}


int op_stop()
{
	char* p = sendbuf;
	set_int(&p, 0);
	set_int(&p, Stop);
	*(int*)sendbuf = p - sendbuf;
	S(sendbuf, p - sendbuf);
	
	printf("command STOP sent\n");
	return 0;
}


void menu()
{
	while(1) {
		  
		printf("1. Get employee\n");
		printf("2. Set employee\n");
		printf("3. Stop\n");
		printf("Option:");
		int op; scanf("%d", &op);
		if(op == 1) {
			printf("ID [1-10]: ");
			int id; scanf("%d", &id);
			op_getemp(id, 0);
		}
		else if(op == 2) {
			printf("ID [1-10]: ");
			int id; scanf("%d", &id);
			op_getemp(id, 1);
			
			printf("Input name: ");
			char name[100]; scanf("%s", name);
			
			printf("Input hours: ");
			char hours[100]; scanf("%s", hours);
			
			op_setemp(id, name, hours);
		}
		else {
			op_stop();
			break;
		}
	}
}


int main(int argc, char* argv[])
{
    if(argc < 2) {
		printf("usage: ./client <client id>\n");
		exit(0);
	}
	
	char* id = argv[1];
	char rdpipe[100]; sprintf(rdpipe, "/tmp/client-%s.fifo", id);
	char wrpipe[100]; sprintf(wrpipe, "/tmp/server-%s.fifo", id);
	
	rd = open(rdpipe, O_RDWR);
	wr = open(wrpipe, O_RDWR);
	assert(rd >= 0);
	assert(wr >= 0);

	menu(); 

	close(rd); 
	close(wr); 
	return 0;
}