
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

#define ICMP_HEADER_LEN 8
#define BUFFER_SIZE 128
#define TIMEOUT 1000

double compareTimes(struct timeval start, struct timeval end)
{
    return (end.tv_sec - start.tv_sec)*1000.0 + (end.tv_usec - start.tv_usec)/1000.0;
}

u_int16_t compute_icmp_checksum (const void *buff, int length)
{
    u_int32_t sum;
    const u_int16_t* ptr = buff;
    for (sum = 0; length > 0; length -= 2)
        sum += *ptr++;
    sum = (sum >> 16) + (sum & 0xffff);
    return (u_int16_t)(~(sum + (sum >> 16)));
}

void output_hoop(int ttl, int nr_replies, char *ips[3], struct timeval send_time[3], struct timeval recv_time[3])
{
// print ttl
    printf("%2d. ", ttl);
// print * if no reply
    if(nr_replies == 0)
        printf("*\n");
    else
    {
// print ip(s)
        if((ips[0] == ips[1]) && (ips[1] == ips[2]))
        {
            printf("%-16s", ips[0]);
        }
        else if(ips[0] == ips[1])
        {
            printf("%-16s", ips[0]);
            printf(" %-16s", ips[2]);
        }
        else if(ips[1] == ips[2])
        {
            printf("%-16s", ips[0]);
            printf(" %-16s", ips[2]);
        }
        else if(ips[0] == ips[2])
        {
            printf("%-16s", ips[0]);
            printf(" %-16s", ips[1]);
        }
        else
        { 
            printf("%-16s", ips[0]);
            printf(" %-16s", ips[1]);
            printf(" %-16s", ips[2]);
        }

// print time or (???)
        if (nr_replies < 3)
            printf("\t???\n"); 
        else
        {
           double sum_time=0;
           for (int i=0; i < 3; i++)
               sum_time += compareTimes(send_time[i], recv_time[i]);
           printf("\t%.3f ms\n", sum_time / 3);
        }
    }
}

int main( int argc, char* argv[] )
{

    if(argc != 2)
    { 
        printf("Usage: sudo ./traceroute <IP>\n");
        exit(1);
    }

    struct icmp icmp_packet;
    int who_replied;
    int stop=0;

    struct timeval send_time[3], recv_time[3];
    struct timeval current_time;
    char *ips[3];

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    current_time.tv_sec = 0;
    current_time.tv_usec = 1000;

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &current_time, sizeof(current_time));

    struct sockaddr_in recipient;
    bzero (&recipient, sizeof(recipient));
    recipient.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &recipient.sin_addr);

    char buffer[BUFFER_SIZE];
    int id = getpid();
    int recv_code;

    for (int ttl = 1; ttl <= 30; ttl++)
    {
        who_replied = 0;

        icmp_packet.icmp_type = ICMP_ECHO;
        icmp_packet.icmp_code = 0;
        icmp_packet.icmp_id = id;
        icmp_packet.icmp_seq = ttl;
        icmp_packet.icmp_cksum = 0;
        icmp_packet.icmp_cksum = compute_icmp_checksum((u_int16_t*)&icmp_packet, 8);


        for (int seq = 0; seq < 3; seq++)
        {
            setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            sendto(sockfd, &icmp_packet, ICMP_HEADER_LEN, 0, (struct sockaddr*)&recipient, sizeof(recipient));
            gettimeofday(&send_time[seq], NULL);
        }

        while (who_replied < 3)
        {
            recv_code = recvfrom (sockfd, buffer, BUFFER_SIZE, 0, 0, 0);
            
            gettimeofday(&current_time, NULL);
            if(recv_code < 0)
            {
                if (compareTimes(send_time[who_replied], current_time) > TIMEOUT) 
                    break;
                continue;
            }

	    struct ip* buff_to_ip = (struct ip*) buffer;

            if (buff_to_ip->ip_p != IPPROTO_ICMP)
                continue;
            
            struct icmp *buff_to_icmp = (struct icmp *) (buffer + buff_to_ip->ip_hl*4);

            if (buff_to_icmp->icmp_type != ICMP_ECHOREPLY && !(buff_to_icmp->icmp_type == ICMP_TIME_EXCEEDED && buff_to_icmp->icmp_code == ICMP_EXC_TTL)) 
                continue;

            if(buff_to_icmp->icmp_type == ICMP_TIME_EXCEEDED)
                buff_to_icmp = (struct icmp *) (buff_to_icmp->icmp_data + ((struct ip *) (buff_to_icmp->icmp_data))->ip_hl*4);

            if(buff_to_icmp->icmp_id != id )
                continue;

            ips[who_replied] = inet_ntoa(buff_to_ip->ip_src);
            gettimeofday(&recv_time[who_replied], NULL);
            who_replied++;

            if(buff_to_icmp->icmp_type == ICMP_ECHOREPLY)
                stop = 1;
        
       }

       output_hoop(ttl, who_replied, ips, send_time, recv_time);

       if(stop == 1)
           break;
   }
}
