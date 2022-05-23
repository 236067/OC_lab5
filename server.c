#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
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
#include <pthread.h>
#include <assert.h>

#define PERM		(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP)
#define MAX_BUF		100000 
#define MAX_CLIENT	100


pthread_t tids[MAX_CLIENT];
int rfds[MAX_CLIENT];
int wfds[MAX_CLIENT];


struct employee
 {
	 int num; // 员工识别号
	 char name[10]; // 员工姓名
	 double hours; // 工作时间
	 pthread_rwlock_t lock;
 };
 

struct employee data[10] = {
	{ 1, "Bob", 10000 }, { 2, "Alice", 20000 },	{ 3, "Tom", 30000 }, { 4, "Jack", 40000 }, { 5, "Jone", 50000 },
		{ 6, "Ken", 60000 }, { 7, "Thomas", 70000 }, { 8, "Kate", 80000 }, { 9, "Willy", 90000 }, { 10, "Joe", 100000 }
};


void init_data()
{
	for(int i = 0; i < 10; ++i) {
		pthread_rwlock_init(&data[i].lock, NULL);
	}
}


typedef enum _Cmd
{
	GetEmp,
	SetEmp,
	Stop
}
Cmd;



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





bool getemp(int id, char* name, char* hours, int w)
{
	for(int i = 0; i < 10; ++i) {
		if(data[i].num == id) {
			if(!w) {
				pthread_rwlock_rdlock(&data[i].lock);
			}
			else {
				pthread_rwlock_wrlock(&data[i].lock);
			}
			strcpy(name, data[i].name);
			sprintf(hours, "%f", data[i].hours);
			
			if(!w) {
				pthread_rwlock_unlock(&data[i].lock);
			}
			return true;
		}
	}
	return false;
}


int handle_getemp(int cid, char* buf, int len)
{
	printf("command GETEMP received\n");
	
	char *p = buf;
	char sendbuf[MAX_BUF];
	
	int id = get_int(&p);
	int w = get_int(&p);
	int ret;
		
	char name[100], hours[100];
	if(getemp(id, name, hours, w)) {
		printf("employee found\n");
		p = sendbuf;
		set_int(&p, 0);
		set_int(&p, 0);
		set_str(&p, name);
		set_str(&p, hours);
		*(int*)sendbuf = p - sendbuf;
		ret = write(wfds[cid], sendbuf, p - sendbuf);
	}
	else {
		printf("employee not found\n");
		p = sendbuf;
		set_int(&p, 0);
		set_int(&p, -1);
		*(int*)sendbuf = p - sendbuf;
		ret = write(wfds[cid], sendbuf, p - sendbuf);
	}
	
	if(ret < 0) {
		printf("send failed: %s\n", strerror(errno));
	}
	return ret > 0 ? 1 : 0;
}


bool setemp(int id, char* name, char* hours)
{
	for(int i = 0; i < 10; ++i) {
		if(data[i].num == id) {
			strcpy(data[i].name, name);
			sscanf(hours, "%lf", &data[i].hours);
			pthread_rwlock_unlock(&data[i].lock);
			return true;
		}
	}
	return false;
}


int handle_setemp(int cid, char* buf, int len)
{
	printf("command SETEMP received\n");
	
	char *p = buf;
	char sendbuf[MAX_BUF];
	
	int id = get_int(&p);
	
	char name[100], hours[100];
	get_str(&p, name);
	get_str(&p, hours);
		
	int ret;

	if(setemp(id, name, hours)) {
		printf("employee updated\n");
		p = sendbuf;
		set_int(&p, 0);
		set_int(&p, 0);
		*(int*)sendbuf = p - sendbuf;
		ret = write(wfds[cid], sendbuf, p - sendbuf);
	}
	else {
		printf("employee not found\n");
		p = sendbuf;
		set_int(&p, 0);
		set_int(&p, -1);
		*(int*)sendbuf = p - sendbuf;
		ret = write(wfds[cid], sendbuf, p - sendbuf);
	}
	
	if(ret < 0) {
		printf("send failed: %s\n", strerror(errno));
	}
	return ret > 0 ? 1 : 0;
}



void server_proc(int id)
{
	char recvbuf[MAX_BUF];	
	
	while(1) {
		int ret = recvn(rfds[id], recvbuf, sizeof(int) * 2);
		if(ret < 0) {
			printf("recv failed: %s\n", strerror(errno));
			break;
		}
		else if(ret == 0) {
			printf("client disconnected\n");
			break;
		}
		
		int len = *(int*)recvbuf;
		int cmd = *(int*)(recvbuf + sizeof(int));
		
		if(len > ret) {
			ret = recvn(rfds[id], recvbuf + ret, len - ret);
			if(ret < 0) {
				printf("recv failed: %s\n", strerror(errno));
				break;
			}
			else if(ret == 0) {
				printf("client %d disconnected\n", id);
				break;
			}
		}
		
		if(cmd == Stop) {
			printf("command STOP received\n");
			printf("client %d disconnected\n", id);
			break;
		}
		
		char* p = recvbuf + sizeof(int) * 2;
		
		if(cmd == GetEmp) {
			handle_getemp(id, p, len); 
		}
		else {
			handle_setemp(id, p, len); 
		}
	}
	
	
}


void* server_thread(void* arg)
{
	int id = (int)arg;
	printf("thread %d started\n", id);
	server_proc(id);
}


int main(int argc, char* argv[])
{
	if(argc < 2) {
		printf("usage: ./server <number of clients>\n");
		exit(0);
	}
	
	int count = atoi(argv[1]);
	
	for(int i = 1; i <= count; ++i) {
		char rdpipe[100]; sprintf(rdpipe, "/tmp/server-%d.fifo", i);
		char wrpipe[100]; sprintf(wrpipe, "/tmp/client-%d.fifo", i);
		
		unlink(rdpipe);
		unlink(wrpipe);
		
		int ret = mkfifo(rdpipe, PERM);
		assert(ret >= 0);
		ret = mkfifo(wrpipe, PERM);
		assert(ret >= 0);
		
		rfds[i] = open(rdpipe, O_RDWR);
		wfds[i] = open(wrpipe, O_RDWR);
		assert(rfds[i] >= 0);
		assert(wfds[i] >= 0);
	}
	
	init_data();
	
	for(int i = 1; i <= count; ++i) {
		pthread_create(&tids[i], NULL, server_thread, (void*)i);
	}
	
	for(int i = 1; i <= count; ++i) {
		void* ret;
		pthread_join(tids[i], &ret);
		
		close(rfds[i]);
		close(wfds[i]);
	}
	return 0;
}
