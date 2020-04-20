#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <iostream>

#define DEFDATALEN  56
#define ICMPID      2
#define IPV6_HOPLIMIT        20
#define IPV6_RECVHOPLIMIT    37
#define SOL_IPV6 IPPROTO_IPV6
#define SOL_RAW IPPROTO_RAW

using namespace std;

struct iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error  "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
};

class Ping {
private:
    sa_family_t af;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    int ttl;

public:
    Ping() {
        af = AF_INET;
        ttl = 0;
    }

    unsigned long long gettime() {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return tv.tv_sec * 1000000ULL + tv.tv_usec;
    }

    unsigned short checksum(unsigned short *addr, int nleft) {
        unsigned sum = 0;
        while (nleft > 1) {
            sum += *addr++;
            nleft -= 2;
        }
        if (nleft == 1) {
            sum += *(unsigned char *) addr;
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return (unsigned short) ~sum;
    }

    void setAF(int v) {
        if (v == 4)
            af = AF_INET;
        else if (v == 6)
            af = AF_INET6;
    }

    void setTTL(int ttl) {
        this->ttl = ttl;
    }

    int setHostName(char *host) {
        int ret;
        struct addrinfo *result = NULL;
        struct addrinfo hint;
        int ai_flags = AI_CANONNAME;
        if (af == AF_INET) {
            struct in_addr in4;
            if (inet_aton(host, &in4) != 0) {
                sin.sin_family = AF_INET;
                sin.sin_addr = in4;
                return 0;
            }
        } else if (af == AF_INET6) {
            struct in6_addr in6;
            if (inet_pton(AF_INET6, host, &in6) > 0) {
                sin6.sin6_family = AF_INET6;
                sin6.sin6_addr = in6;
                return 0;
            }
        }
        memset(&hint, 0, sizeof(hint));
        hint.ai_family = af;
        hint.ai_socktype = SOCK_STREAM;
        hint.ai_flags = ai_flags & ~AI_CANONNAME;
        ret = getaddrinfo(host, NULL, &hint, &result);
        if (ret || !result) {
            if (result != NULL)
                freeaddrinfo(result);
            printf("Error getaddrinfo\n");
            return -1;
        }
        if (af == AF_INET)
            memcpy(&sin, result->ai_addr, result->ai_addrlen);
        else
            memcpy(&sin6, result->ai_addr, result->ai_addrlen);
        freeaddrinfo(result);
        return 0;
    }

    void ping4Loop() {
        int sockopt;
        int sockfd = socket(AF_INET, SOCK_RAW, 1);
        if (sockfd < 0) {
            printf("Error creating socket, %s\n", strerror(errno));
            return;
        }
        sockopt = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &sockopt, sizeof(int));
        sockopt = 8192;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sockopt, sizeof(int));
        if (ttl != 0) {
            setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
            setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(int));
        }
        int seq = 0;
        void *sendbuf = malloc(DEFDATALEN + ICMP_MINLEN + 4);
        void *recvbuf = malloc(DEFDATALEN + ICMP_MINLEN + 4);
        struct icmp *pkt = (struct icmp *) sendbuf;

        while (1) {
            memset(pkt, 0, DEFDATALEN + ICMP_MINLEN + 4);
            pkt->icmp_type = ICMP_ECHO;
            pkt->icmp_cksum = 0;
            pkt->icmp_seq = seq++;
            pkt->icmp_id = ICMPID;
            *(uint32_t *) &pkt->icmp_dun = gettime();
            pkt->icmp_cksum = checksum((uint16_t *) pkt, DEFDATALEN + ICMP_MINLEN);
            unsigned long long xtime = gettime();
            if ((DEFDATALEN + ICMP_MINLEN) !=
                sendto(sockfd, sendbuf, DEFDATALEN + ICMP_MINLEN, 0, (sockaddr *) &sin, sizeof(sin))) {
                printf("Error sending packet\n");
            } else {
                fd_set fd_socket_set;
                struct timeval tv;
                int recvflag = 0;
                FD_ZERO(&fd_socket_set);
                FD_SET(sockfd, &fd_socket_set);
                tv.tv_sec = 2;
                tv.tv_usec = 0;
                while (recvflag == 0 && (gettime() - xtime) < 2000000)
                    if (select(sockfd + 1, &fd_socket_set, NULL, NULL, &tv) > 0) {
                        struct sockaddr_in from;
                        socklen_t fromlen = (socklen_t) sizeof(from);
                        int c;
                        struct icmp *icmppkt;
                        struct iphdr *iphdr;
                        int hlen;

                        c = recvfrom(sockfd, recvbuf, DEFDATALEN + ICMP_MINLEN + 4, 0,
                                     (struct sockaddr *) &from, &fromlen);
                        if (c >= DEFDATALEN + ICMP_MINLEN) {
                            iphdr = (struct iphdr *) recvbuf;
                            hlen = iphdr->ihl << 2;
                            c -= hlen;
                            icmppkt = (struct icmp *) ((char *) recvbuf + hlen);
                            if (icmppkt->icmp_id == ICMPID && icmppkt->icmp_type == ICMP_ECHOREPLY) {
                                uint16_t recv_seq = ntohs(icmppkt->icmp_seq);
                                uint32_t *tp = NULL;
                                if (c >= ICMP_MINLEN + sizeof(uint32_t)) {
                                    tp = (uint32_t *) icmppkt->icmp_data;
                                    *tp = gettime() - *tp;
                                }
                                printf("RTT time = %d.%dms, ttl = %d, ", *tp / 1000, *tp % 1000, iphdr->ttl);
                                recvflag = 1;
                            }
                        }
                    }
                if (recvflag == 0)
                    printf("packet lost\n");
                else {
                    printf("no packet loss\n");
                }
            }
            xtime = gettime() - xtime;
            if (xtime < 2000000)
                usleep(2000000 - xtime);
        }
    }

    void ping6Loop() {
        int sockopt;
        int seq = 0;
        int sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (sockfd < 0) {
            printf("Error creating socket, %s\n", strerror(errno));
            return;
        }
        struct msghdr msg;
        struct sockaddr_in6 from;
        struct iovec iov;
        char control_buf[512];
        sockopt = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &sockopt, sizeof(int));
        sockopt = 8192;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sockopt, sizeof(int));
        sockopt = offsetof(struct icmp6_hdr, icmp6_cksum);
        setsockopt(sockfd, SOL_RAW, IPV6_CHECKSUM, &sockopt, sizeof(int));
        if (ttl != 0) {
            setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(int));
            setsockopt(sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(int));
        }
        sockopt = 1;
        setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &sockopt, sizeof(int));
        setsockopt(sockfd, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &sockopt, sizeof(int));
        setsockopt(sockfd, IPPROTO_IPV6, IPV6_HOPLIMIT, &sockopt, sizeof(int));
        void *sendbuf = malloc(DEFDATALEN + sizeof(struct icmp6_hdr));
        void *recvbuf = malloc(DEFDATALEN + sizeof(struct icmp6_hdr));
        while (1) {
            msg.msg_name = &from;
            msg.msg_namelen = sizeof(from);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control_buf;
            iov.iov_base = recvbuf;
            iov.iov_len = DEFDATALEN + sizeof(struct icmp6_hdr);
            struct icmp6_hdr *pkt = (struct icmp6_hdr *) sendbuf;
            memset(pkt, 0, DEFDATALEN + sizeof(struct icmp6_hdr));
            pkt->icmp6_type = ICMP6_ECHO_REQUEST;
            pkt->icmp6_code = 0;
            pkt->icmp6_seq = seq++;
            pkt->icmp6_id = ICMPID;
            *(unsigned int *) (&pkt->icmp6_data8[4]) = gettime();
            unsigned long long xtime = gettime();
            if ((DEFDATALEN + sizeof(struct icmp6_hdr)) !=
                sendto(sockfd, sendbuf, DEFDATALEN + sizeof(struct icmp6_hdr), 0, (sockaddr *) &sin6, sizeof(sin6))) {
                printf("Error sending packet\n");
            } else {
                int c;
                struct cmsghdr *mp;
                int ttl = -1;
                int recvflag = 0;
                while (recvflag == 0 && (gettime() - xtime) < 2000000) {
                    msg.msg_controllen = sizeof(control_buf);
                    c = recvmsg(sockfd, &msg, 0);
                    if (c == (DEFDATALEN + sizeof(struct icmp6_hdr))) {
                        for (mp = CMSG_FIRSTHDR(&msg); mp; mp = CMSG_NXTHDR(&msg, mp)) {
                            if (mp->cmsg_level == SOL_IPV6
                                && mp->cmsg_type == IPV6_HOPLIMIT
                                    ) {
                                ttl = *(int *) (CMSG_DATA(mp));
                            }
                        }
                        struct icmp6_hdr *icmpv6 = (struct icmp6_hdr *) recvbuf;
                        if (icmpv6->icmp6_id == ICMPID && icmpv6->icmp6_type == ICMP6_ECHO_REPLY) {
                            unsigned int *tp = (unsigned int *) (&icmpv6->icmp6_data8[4]);
                            *tp = gettime() - *tp;
                            printf("RTT time = %d.%dms, ttl = %d, ", *tp / 1000, *tp % 1000, ttl);
                            recvflag = 1;
                        }
                    }
                }
                if (recvflag == 0)
                    printf("packet lost\n");
                else {
                    printf("no packet loss\n");
                }
            }
            xtime = gettime() - xtime;
            if (xtime < 2000000)
                usleep(2000000 - xtime);
        }
    }

    void runLoop() {
        if (af == AF_INET6)
            ping6Loop();
        else
            ping4Loop();
    }

    void usage(char *p) {
        cout << "Usage:  " << p << " [-4|-6] [-t ttl]  hostname|ip" << endl;
        exit(0);
    }
};

int main(int argc, char *argv[]) {
    int i;
    Ping ping;

    if (argc < 2)
        ping.usage(argv[0]);

    for (i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-4") == 0)
            ping.setAF(4);
        else if (strcmp(argv[i], "-6") == 0)
            ping.setAF(6);
        else if (strcmp(argv[i], "-t") == 0) {
            i++;
            ping.setTTL(atoi(argv[i]));
        }
    }
    if (0 == ping.setHostName(argv[argc - 1]))
        ping.runLoop();
    return 0;
}
