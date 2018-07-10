#ifndef ONVIFHELPER_HEADER
#define ONVIFHELPER_HEADER

#include <string>
#include <list>

class ONVIFHelper
{
  public:
    struct CameraAddress
    {
      CameraAddress():
        ipAddress(""),
        port(""){}
      std::string ipAddress;
      std::string port;
    };

    struct MediaInfo
    {
      MediaInfo():
        protoType(""),
        ipAddress(""),
        port(""),
        mediaPath(""){}
      std::string protoType;
      std::string ipAddress;
      std::string port;
      std::string mediaPath;
    };
  public:
    static std::list<CameraAddress> search(); 
    static MediaInfo getMediaUri(std::string hostIP,std::string hostPort,std::string userName,std::string passWord);
};

#endif
