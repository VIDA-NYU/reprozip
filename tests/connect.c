/* connect.c
 *
 * Connects to a TCP server.
 *
 * usage: ./connect
 */

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>


int main(void)
{
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    {
        struct hostent *h = gethostbyname("www.google.com");
        if(h == NULL)
            return 1;
        addr.sin_addr = *((struct in_addr*)h->h_addr);
    }
    addr.sin_port = htons(80);

    if(connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
        return 2;

    close(sockfd);

    return 0;
}
