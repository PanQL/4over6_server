#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <sys/epoll.h>
#include <linux/ip.h>

#define DEFAULT_SERVER_PORT 6666	// 服务器接口
#define CLIENT_QUEUE_LENGTH 10

// Message types
/*
	100: IP request
	101: IP response
	102: Network request
	103: Network response
	104: Keepalive
*/

#define IP_REQUEST 100	// 客户端连接请求
#define IP_RESPONSE 101 // 答复客户端的连接请求
#define NETWORK_REQUEST 102 // 客户端的转发请求
#define NETWORK_RESPONSE 103	// 答复客户端的转发
#define KEEPALIVE 104	// 客户端的存活确认
#define MSG_HEADER_SIZE 8 // 消息长度

struct Msg {
	int length;
	char type;
	char data[4096];
};

#define IP_TO_UINT(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))

#define N_USERS 100
#define IP_POOL_START IP_TO_UINT(10, 233, 233, 100)

pthread_mutex_t MUTEX;
struct user_info {
	int fd;
	int count;
	int secs;
	struct in_addr v4addr;
	struct in6_addr v6addr;
} user_info_table[N_USERS];

int listenfd;	// 服务器socket
int tun_fd;	// 虚接口
int epfd;
struct epoll_event ev;	// 临时epoll事件，用于添加删除

void add_to_epoll(int fd) {
	ev.data.fd= fd;
	ev.events = EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_ADD, fd,&ev);
}

void remove_from_epoll(int fd) {
	ev.data.fd= fd;
	ev.events = EPOLLIN;
	epoll_ctl(epfd, EPOLL_CTL_DEL, fd,&ev);
}

void create_server() {
	// Create socket
	listenfd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (listenfd == -1) {
		perror("socket()");
		exit(EXIT_FAILURE);
	}
	
	// Bind address
	int server_port = DEFAULT_SERVER_PORT;
	struct sockaddr_in6 server_addr;
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(server_port);
	int ret = bind(listenfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
	if (ret == -1) {
		perror("bind()");
		close(listenfd);
		exit(EXIT_FAILURE);
	}
}
	
void start_server() {
	// Listen
	int ret = listen(listenfd, CLIENT_QUEUE_LENGTH);
	if (ret == -1) {
		perror("listen()");
		close(listenfd);
		exit(EXIT_FAILURE);
	}
}

void init_user_info_table() {
	for (int i = 0; i < N_USERS; i++) {
		user_info_table[i].v4addr.s_addr = htonl(IP_POOL_START + i);
		user_info_table[i].fd = -1;
	}
}

int tun_alloc(char *dev) {
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Error creating TUN\n");
		return fd;
	}
	
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags |= IFF_TUN | IFF_NO_PI;
	
	if (dev && *dev != 0) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}
	
	int err = ioctl(fd, TUNSETIFF, (void *) &ifr);
	if (err < 0) {
		fprintf(stderr, "Error setting tunnel name\n");
		close(fd);
		exit(EXIT_FAILURE);
	}
	
	if (dev) {
		strcpy(dev, ifr.ifr_name);
		fprintf(stderr, "%s \n", dev);
	}
	
	return fd;
}

void init_tun() {
	char tun_name[IFNAMSIZ];
	tun_name[0] = 0;
	tun_fd = tun_alloc(tun_name);
}

void response_ip_request(int fd, struct user_info *u_info) {
	struct Msg msg;
	msg.type = IP_RESPONSE;
	char ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(u_info->v4addr), ip_str, INET_ADDRSTRLEN);
	sprintf(msg.data, "%s 0.0.0.0 8.8.8.8 202.38.120.242 202.106.0.20 ", ip_str);
	int length = strlen(msg.data) + sizeof(struct Msg) - 4096;
	msg.length = length;
	if (send(fd, &msg, length, 0) < 0) {
		fprintf(stderr, "respoise ip request failed!");
	}
}

// ip is in network byte order
struct user_info *find_user_by_v4ip(uint32_t ip) {
	pthread_mutex_lock(&MUTEX);
	for (int i = 0; i < N_USERS; i++) {
		if (user_info_table[i].fd != -1 && *(uint32_t *) &user_info_table[i].v4addr == ip) {
			pthread_mutex_unlock(&MUTEX);
			return user_info_table + i;
		}
	}
	pthread_mutex_unlock(&MUTEX);
	return NULL;
}


struct user_info *find_user_by_fd(uint32_t fd) {
	pthread_mutex_lock(&MUTEX);
	for (int i = 0; i < N_USERS; i++) {
		if (user_info_table[i].fd == fd) {
			pthread_mutex_unlock(&MUTEX);
			return user_info_table + i;
		}
	}
	pthread_mutex_unlock(&MUTEX);
	return NULL;
}


void free_user_by_fd(uint32_t fd) {
	pthread_mutex_lock(&MUTEX);
	for (int i = 0; i < N_USERS; i++) {
		if (user_info_table[i].fd == fd) {
			user_info_table[i].fd = -1;
		}
	}
	pthread_mutex_unlock(&MUTEX);
}

char packet_buffer[1500];
struct Msg msg_buffer;
void process_packet() {
	int ret = read(tun_fd, (void *)packet_buffer, 1500);	// 读取一个ip头
	if ( ret < 0 ) {	// 如果包大小小于一个ip头，则忽略
		fprintf(stderr ,"error! %d \n", tun_fd);
		return;
	}

	struct iphdr *hdr = (struct iphdr*)packet_buffer;
	int length = ntohs(hdr->tot_len);
	int dst_addr = hdr->daddr;
	char buf1[16], buf2[16];
	inet_ntop(AF_INET, &hdr->saddr, buf1, sizeof(buf1));
	inet_ntop(AF_INET, &hdr->daddr, buf2, sizeof(buf2));
	fprintf(stderr, "a packet from %s to %s , size : %x ", buf1, buf2, length);

	if ( IP_POOL_START < dst_addr < IP_POOL_START + N_USERS ) {
		struct user_info *u_info = find_user_by_v4ip(dst_addr);
		if ( u_info == NULL ) {
			fprintf(stderr, "can not find addr %s \n", buf2);
			return;
		}
		int fd = u_info->fd;

		msg_buffer.type = NETWORK_RESPONSE;
		msg_buffer.length = length + MSG_HEADER_SIZE;
		memcpy(msg_buffer.data, packet_buffer, length);

		length += MSG_HEADER_SIZE;
		ret = send(fd, (void*)&msg_buffer, length, 0);
		fprintf(stderr, " the ret %d \n", ret);
		if ( ret < 0 ) {
			/*close(fd);*/
			/*free_user_by_fd(fd);*/
			/*remove_from_epoll(fd);*/
			/*fprintf(stderr, "process_packet : %d is disconnected \n", fd);*/
			return;
		}
	}		
	memset(packet_buffer, 0, 1500);
}

char keepalive_buf[8];
void *keepalive_thread_func() {
	pthread_mutex_lock(&MUTEX);
	while(1) {
		pthread_mutex_unlock(&MUTEX);
		sleep(1);
		pthread_mutex_lock(&MUTEX);
		for ( int i = 0; i < N_USERS; i++ ) {
			int fd = user_info_table[i].fd;
			if ( fd == -1) {
				continue;
			}
			if ( time(NULL) - user_info_table[i].secs > 60) {
				user_info_table[i].fd = -1;
				close(fd);
				remove_from_epoll(fd);
			} else {
				user_info_table[i].count -= 1;
				if ( user_info_table[i].count == 0) {
					struct Msg *k_msg = (struct Msg *)keepalive_buf;
					k_msg->type = KEEPALIVE;
					k_msg->length = MSG_HEADER_SIZE;
					send(fd, (void *)k_msg, k_msg->length, 0);
					user_info_table[i].count = 5;
				}
			}
		}
	}
}

void main() {
	int nfds, connfd, fd, ret;
	struct sockaddr_in6 clientaddr;
	int client_len = sizeof(clientaddr);
	char str_addr[INET6_ADDRSTRLEN];	// 用于获取某个客户端地址
	struct Msg msg;
	// 创建用于注册的epoll事件以及用于拷贝可读事件的数组
	struct epoll_event events[20];
	epfd = epoll_create(256);	// 创建一个epoll

	create_server();
	add_to_epoll(listenfd);
	start_server();
	init_user_info_table();

	init_tun();
	fprintf(stderr, "tun fd is %d \n", tun_fd);
	add_to_epoll(tun_fd);


	pthread_t keepalive_thread;
	ret = pthread_create(&keepalive_thread, NULL, keepalive_thread_func, NULL);
	if (ret == -1) {
		fprintf(stderr, "pthread_create() \n");
		close(listenfd);
		close(tun_fd);
		exit(-1);
	}
	fprintf(stderr, "keep alive thread start \n");
	ret = 0;

	fprintf(stderr, "%ld", sizeof(struct Msg));
	while(1) {
		nfds = epoll_wait(epfd,events,20,500);
		for(int i = 0; i < nfds; i ++) {
			if(events[i].data.fd == listenfd) {
				connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &client_len);
				if (connfd == -1) {
					perror("accept failed");
					close(connfd);
					exit(-1);
				}

				int i = 0;
				pthread_mutex_lock(&MUTEX);
				for (; i < N_USERS; i++) {
					if (user_info_table[i].fd == -1) {
						user_info_table[i].fd = connfd;
						memcpy(&(user_info_table[i].v6addr), &clientaddr, sizeof(struct sockaddr));
						user_info_table[i].secs = time(NULL);
						user_info_table[i].count = 5;
						break;
					}
				}
				pthread_mutex_unlock(&MUTEX);

				if (i == N_USERS ) {
					fprintf(stderr, "too many client!");
					continue;
				}
				i = 0;

				add_to_epoll(connfd);

				inet_ntop(AF_INET6, &(clientaddr.sin6_addr), str_addr, sizeof(str_addr));
				printf("New connection from %s %d\n", str_addr, ntohs(clientaddr.sin6_port));
			}else if(events[i].data.fd == tun_fd) {
				process_packet();
			}else if(events[i].events & EPOLLIN){
				fd = events[i].data.fd;
				struct user_info *u_info = find_user_by_fd(fd);
				if (u_info == NULL) {
					continue;
				}

				ret = recv(fd, (void *)&msg, 8, 0);
				if ( ret <= 0) {
					/*close(fd);*/
					/*free_user_by_fd(fd);*/
					/*remove_from_epoll(fd);*/
					/*fprintf(stderr, "recv msg : %d is disconnected \n", fd);*/
					continue;
				}
				while(ret < 8) {	
					ret += recv(fd, (void *)&msg + ret, 8 - ret, 0);
				}
				int len = msg.length;
				while(ret < len) {
					ret += recv(fd, (void *)&msg + ret, len - ret, 0);
				}
				ret = 0;

				if ( u_info == NULL ) {
					fprintf(stderr, "not user info for fd %d \n", fd);
					continue;
				}
				if (msg.type == IP_REQUEST) {
					fprintf(stderr, "recv a ip request \n");
					response_ip_request(fd, u_info);
				}else if(msg.type == NETWORK_REQUEST) {
					fprintf(stderr, "recv a network request \n");
					ret = 0;
					int len = msg.length - 8;
					ret += write(tun_fd, msg.data + ret, len - ret);
					/*fprintf(stderr, "write %d bytes into tun_fd \n", ret);*/
				}else if(msg.type == KEEPALIVE) {
					fprintf(stderr, "recv a keep alive packet \n");
					pthread_mutex_lock(&MUTEX);
					u_info->secs = time(NULL);
					pthread_mutex_unlock(&MUTEX);
				}else{
					fprintf(stderr, "recv a unknown packet, type is %d \n", (int)msg.type);
				}
			}
		}
	}

	close(epfd);	// epoll占用一个描述符，需要手动释放
	return;
}
