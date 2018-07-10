#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>


std::string getLocalAddress()
{
  std::string address;
  int socketHandle=socket(PF_INET,SOCK_STREAM,0);
  if(socketHandle<0)
  {
    std::cout<<"failed to create socket"<<std::endl;
    std::cout<<"err : "<<strerror(errno)<<std::endl;
    return address;
  }
  struct sockaddr_in addr;
  memset(&addr,0,sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_port=htons(0);
  addr.sin_addr.s_addr=inet_addr("8.8.8.8");
  int ret=connect(socketHandle,(struct sockaddr*)&addr,sizeof(addr));
  if(ret<0)
  {
    std::cout<<"failed to create socket"<<std::endl;
    std::cout<<"err : "<<strerror(errno)<<std::endl;
    return address;
  }
  struct sockaddr_in peerAddr; 
  socklen_t len=sizeof(peerAddr);
  getsockname(socketHandle,(struct sockaddr*)&peerAddr,&len);
  char* peerAddress=inet_ntoa(peerAddr.sin_addr);
  std::cout<<"ip : "<<inet_ntoa(peerAddr.sin_addr)<<std::endl;
  std::cout<<"port : "<<ntohs(peerAddr.sin_port)<<std::endl;
  address.append(peerAddress);
  return address;

}

int main()
{
  std::string addr=getLocalAddress();
  std::cout<<"addr : "<<addr<<std::endl;
  return 0;
}
