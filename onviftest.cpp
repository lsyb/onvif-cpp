#include "ONVIFHelper.h"
#include <iostream>
int main()
{
  std::list<ONVIFHelper::CameraAddress> addrs=ONVIFHelper::search();
  if(addrs.size()<1)
  {
    std::cout<<"no camera found"<<std::endl;
    return 0;
  }
  for(std::list<ONVIFHelper::CameraAddress>::iterator camIter=addrs.begin();camIter!=addrs.end();camIter++)
  {
    ONVIFHelper::MediaInfo info=ONVIFHelper::getMediaUri(camIter->ipAddress,camIter->port,"admin","123456");
    std::cout<<"ip : "<<info.ipAddress<<std::endl;
    std::cout<<"port : "<<info.port<<std::endl;
    std::cout<<"mediaPath : "<<info.mediaPath<<std::endl;
    std::cout<<"type : "<<info.protoType<<std::endl;
  }
  return 0;
}
