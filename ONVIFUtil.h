#ifndef ONVIFUTIL_HEADER
#define ONVIFUTIL_HEADER

#include <string>
#include <list>
#include <map>

class ONVIFUtil
{
  public:
    struct XMLElement
    {
      std::string name;
      std::string value;
      std::map<std::string,std::string> attrs;
    };
  public:
    static std::string getUUID();
    static std::string generateAuthStr(std::string userName,std::string passWord);
    static std::string unicastExcuteAction(std::string hostip,std::string port,std::string action);
    static std::list<std::string> multicastExcuteAction(std::string hostip,std::string port,std::string action);
    static std::list<XMLElement> getElementValueByName(std::string xmlStr,std::string name);
    static std::list<std::string> getElementValueByPath(std::string xmlStr,std::string path);
};


#endif
