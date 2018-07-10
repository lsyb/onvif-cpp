#include "ONVIFHelper.h"
#include "ONVIFUtil.h"
#include <iostream>


#define ARG_MESSAGEID "[MessageID]"
#define ARG_AUTHSTRING "[AuthString]"
#define ARG_PROBESCOPE "[ProbeScope]"
#define ARG_PROFILETOKEN "[ProfileToken]"

#define KEY_PROBEXADDRS "XAddrs"

const char actionProbeFmtStr[]="<Envelope xmlns=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">" \
                                "<Header><wsa:MessageID xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">" \
                                ARG_MESSAGEID \
                                "</wsa:MessageID>" \
                                "<wsa:To xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">" \
                                "urn:schemas-xmlsoap-org:ws:2005:04:discovery" \
                                "</wsa:To>" \
                                "<wsa:Action xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">" \
                                "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>" \
                                "</Header>" \
                                "<Body>" \
                                "<Probe xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" \
                                "<Scopes />" \
                                "</Probe>" \
                                "</Body>" \
                                "</Envelope>";



const char actionGetProfileFmtStr[]="<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">" \
                                     "<s:Header>" \
                                     ARG_AUTHSTRING \
                                     "</s:Header>" \
                                     "<s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">" \
                                     "<GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\">" \
                                     "</GetProfiles></s:Body></s:Envelope>"; 
const char actionGetStreamUriFmtStr[]="<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">" \
                                       "<s:Header>" \
                                       ARG_AUTHSTRING \
                                       "</s:Header>" \
                                       "<s:Body xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">" \
                                       "<GetStreamUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\">" \
                                       "<StreamSetup><Stream xmlns=\"http://www.onvif.org/ver10/schema\">RTP-Unicast</Stream><Transport xmlns=\"http://www.onvif.org/ver10/schema\"><Protocol>RTSP</Protocol></Transport></StreamSetup>" \
                                       "<ProfileToken>" \
                                       ARG_PROFILETOKEN \
                                       "</ProfileToken>" \
                                       "</GetStreamUri></s:Body></s:Envelope>";


std::list<ONVIFHelper::CameraAddress> ONVIFHelper::search()
{
  std::list<ONVIFHelper::CameraAddress> cameraAddress;
  std::string uuidStr=ONVIFUtil::getUUID();
  std::string actionProbeStr=actionProbeFmtStr;
  actionProbeStr.replace(actionProbeStr.find(ARG_MESSAGEID),sizeof(ARG_MESSAGEID)-1,uuidStr);
  std::list<std::string> respones=ONVIFUtil::multicastExcuteAction("239.255.255.250","3702",actionProbeStr);
  for(std::list<std::string>::iterator it=respones.begin();it!=respones.end();it++)
  {
    //for MediaInfo::mediaHost
    std::string onvifHost;
    std::string::size_type XAddrsStartPos=it->find(KEY_PROBEXADDRS);
    if(XAddrsStartPos==std::string::npos)
      continue;
    XAddrsStartPos=it->find("http://",XAddrsStartPos)+7;
    int XAddrsEndPos=it->find("/",XAddrsStartPos);
    onvifHost=it->substr(XAddrsStartPos,XAddrsEndPos-XAddrsStartPos);

    //for MediaInfo::mediaUrl
    int hostIPStartPos=0;
    int hostIPEndPos=onvifHost.find(":");
    std::string hostIP=onvifHost.substr(hostIPStartPos,hostIPEndPos-hostIPStartPos);
    int hostPortStartPos=hostIPEndPos+1;
    int hostPortEndPos=onvifHost.size();
    std::string hostPort=onvifHost.substr(hostPortStartPos,hostPortEndPos-hostPortStartPos);
    ONVIFHelper::CameraAddress address;
    address.ipAddress=hostIP;
    address.port=hostPort;
    cameraAddress.push_back(address);
   }
  return cameraAddress;
}

ONVIFHelper::MediaInfo ONVIFHelper::getMediaUri(std::string hostIP,std::string hostPort,std::string userName,std::string passWord)
{
  ONVIFHelper::MediaInfo info;
  std::string actionGetProfileStr=actionGetProfileFmtStr;
  actionGetProfileStr.replace(actionGetProfileStr.find(ARG_AUTHSTRING),sizeof(ARG_AUTHSTRING)-1,ONVIFUtil::generateAuthStr(userName,passWord));
  std::string profileRespone=ONVIFUtil::unicastExcuteAction(hostIP,hostPort,actionGetProfileStr);
  if(profileRespone.empty())
    return info;
  std::list<ONVIFUtil::XMLElement> elementS=ONVIFUtil::getElementValueByName(profileRespone,"Profiles");
  std::string actionGetStreamUriStr=actionGetStreamUriFmtStr;
  actionGetStreamUriStr.replace(actionGetStreamUriStr.find(ARG_AUTHSTRING),sizeof(ARG_AUTHSTRING)-1,ONVIFUtil::generateAuthStr(userName,passWord));
  actionGetStreamUriStr.replace(actionGetStreamUriStr.find(ARG_PROFILETOKEN),sizeof(ARG_PROFILETOKEN)-1,elementS.begin()->attrs["token"]);
  std::string mediaUriRespone=ONVIFUtil::unicastExcuteAction(hostIP,hostPort,actionGetStreamUriStr);
  if(mediaUriRespone.empty())
    return info;
  std::list<ONVIFUtil::XMLElement> mediaUriList=ONVIFUtil::getElementValueByName(mediaUriRespone,"Uri");
  if(mediaUriList.size()<1)
    return info;
  std::string mediaUriStr=mediaUriList.begin()->value;

  int protoTypeStart=0;
  int protoTypeEnd=protoTypeEnd=mediaUriStr.find("://",protoTypeStart);
  std::string protoType=mediaUriStr.substr(protoTypeStart,protoTypeEnd-protoTypeStart);

  int ipAddressStart=protoTypeEnd+3;
  int ipAddressEnd=mediaUriStr.find('/',ipAddressStart);
  ipAddressEnd=mediaUriStr.rfind(':',ipAddressEnd);
  std::string ipAddress=mediaUriStr.substr(ipAddressStart,ipAddressEnd-ipAddressStart);

  int portStart=ipAddressEnd+1;
  int portEnd=mediaUriStr.find('/',portStart);
  std::string port=mediaUriStr.substr(portStart,portEnd-portStart);

  int mediaPathStart=portEnd;
  int mediaPathEnd=mediaUriStr.size();
  std::string mediaPath=mediaUriStr.substr(mediaPathStart,mediaPathEnd-mediaPathStart);

  info.protoType=protoType;
  info.ipAddress=ipAddress;
  info.port=port;
  info.mediaPath=mediaPath;
  return info;
}

