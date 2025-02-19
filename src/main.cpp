#include <CMDLine.h>

int tcp_timeout = 600;
int udp_timeout = 600;

int main(int argc, char *argv[])
{
    parse_arguments(argc, argv, &tcp_timeout, &udp_timeout);
    
    return 0;
}
