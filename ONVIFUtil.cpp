#include "ONVIFUtil.h"
#include <openssl/ssl.h>
#include <uuid/uuid.h>
#include "base64.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>

struct NodeScope
{
  std::string::size_type startElementStart;
  std::string::size_type startElementEnd;
  std::string::size_type endElementStart;
  std::string::size_type endElementEnd; 
  bool isValid;
  public:
  NodeScope():
    startElementStart(-1),
    startElementEnd(-1),
    endElementStart(-1),
    endElementEnd(-1){}
  void clear()
  {
    startElementStart=-1;
    startElementEnd=-1;
    endElementStart=-1;
    endElementEnd=-1;
  }
};

#define ARG_AUTH_USERNAME "[Auth_UserName]"
#define ARG_AUTH_DIGEST "[Auth_Digest]"
#define ARG_AUTH_NONCE "[Auth_Nonce]"
#define ARG_AUTH_TIMESTAMP "[Auth_TimeStamp]"

#define ARG_HEADER_CONTENT_LENGTH "[Header_ContentLength]"
#define ARG_HEADER_HOST "[Header_Host]"

const char headerFmtStr[]="POST /onvif/device_service HTTP/1.1\r\n" \
                           "Host: " ARG_HEADER_HOST "\r\n" \
                           "Content-Type: application/soap+xml\r\n" \
                           "Content-Length: " ARG_HEADER_CONTENT_LENGTH "\r\n\r\n";

const char  authFmtStr[]="<Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">" \
                          "<UsernameToken>" \
                          "<Username>" \
                          ARG_AUTH_USERNAME \
                          "</Username>" \
                          "<Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">" \
                          ARG_AUTH_DIGEST \
                          "</Password>" \
                          "<Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" \
                          ARG_AUTH_NONCE \
                          "</Nonce>" \
                          "<Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" \
                          ARG_AUTH_TIMESTAMP \
                          "</Created>" \
                          "</UsernameToken>" \
                          "</Security>";

std::list<NodeScope> getNodeScope(std::string xmlStr,std::string nodeName)
{
  std::list<NodeScope> scopeS;
  std::string::size_type startPos=0;
  std::string::size_type endPos=0;
  NodeScope scope;
  while((startPos=xmlStr.find('<',endPos))!=std::string::npos && (endPos=xmlStr.find('>',startPos))!=std::string::npos)
  {
    std::string::size_type nameStart=0;
    std::string::size_type nameEnd=0;
    nameEnd=xmlStr.find(' ',startPos);
    if(nameEnd>endPos || nameEnd==std::string::npos)
      nameEnd=endPos;
    nameStart=xmlStr.rfind(':',nameEnd);
    if(nameStart<startPos || nameStart==std::string::npos)
      nameStart=startPos;
    nameStart+=1;
    std::string name=xmlStr.substr(nameStart,nameEnd-nameStart);
    if(name==nodeName)
    {
      std::string::size_type slashPos=xmlStr.find('/',startPos);
      if(slashPos>nameEnd || slashPos==std::string::npos)
      {
        scope.startElementStart=startPos;
        scope.startElementEnd=endPos+1;
      }
      else
      {
        scope.endElementStart=startPos;
        scope.endElementEnd=endPos+1;
        scopeS.push_back(scope);
        scope.clear();
      }
    }
  }
  return scopeS;
}

void stripSpaceHeadAndTail(std::string& str)
{
  int length=str.size(); 
  int alphaStart=0;
  int alphaEnd=0;
  for(int n=0;n<length;n++)
  {
    if(str[n]!=' ' && str[n]!='\t')
      break;
    alphaStart++;
  }
  for(int n=length-1;n>=0;n--)
  {
    if(str[n]!=' ' && str[n]!='\t')
      break;
    alphaEnd++;
  }
  if(alphaStart==length-1 || alphaEnd==length-1)
    str="";
  else
  {
    str.replace(str.size()-alphaEnd,alphaEnd,"");
    str.replace(0,alphaStart,"");
  }
}

std::map<std::string,std::string> getAttrs(std::string element)
{
  std::map<std::string,std::string> attrS;
  std::string::size_type attrNameStart=0;
  std::string::size_type attrNameEnd=0;
  std::string::size_type attrValueStart=0;
  std::string::size_type attrValueEnd=0;
  while((attrNameStart=element.find(' ',attrValueEnd))!=std::string::npos && (attrNameEnd=element.find('=',attrNameStart))!=std::string::npos && (attrValueStart=element.find('\"',attrNameEnd))!=std::string::npos && (attrValueEnd=element.find('\"',attrValueStart+1))!=std::string::npos)
  {
    std::string attrName=element.substr(attrNameStart,attrNameEnd-attrNameStart);
    std::string attrValue=element.substr(attrValueStart+1,attrValueEnd-attrValueStart-1);
    stripSpaceHeadAndTail(attrName);
    stripSpaceHeadAndTail(attrValue);
    attrS.insert(std::pair<std::string,std::string>(attrName,attrValue));
    attrNameStart=attrValueEnd+1;
  }
  return attrS;
}

std::string ONVIFUtil::getUUID()
{
  uuid_t uuidBinary;
  uuid_generate(uuidBinary);
  uuid_string_t uuidChars;
  uuid_unparse_lower(uuidBinary,uuidChars);
  std::string uuidStr=uuidChars;
  return uuidStr;
}

std::string ONVIFUtil::generateAuthStr(std::string userName,std::string passWord)
{
  std::string uuidStr=getUUID();

  time_t t=time(NULL);
  //struct tm* lt=localtime(&t);
  struct tm* lt=gmtime(&t);
  char timeStamp[100];
  memset(timeStamp,0,100);
  sprintf(timeStamp,"%04d-%02d-%02dT%02d:%02d:%02d:123Z",lt->tm_year+1900,lt->tm_mon+1,lt->tm_mday,lt->tm_hour,lt->tm_min,lt->tm_sec);
  srandom(t+(long)userName.data()+(long)passWord.data());
  int randNum=random();
  char nonce[100];
  memset(nonce,0,100);
  sprintf(nonce,"%d",randNum);

  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  OpenSSL_add_all_digests();
  md = EVP_get_digestbyname("sha1");
  EVP_MD_CTX_init(&mdctx);
  EVP_DigestInit_ex(&mdctx, md, NULL);
  EVP_DigestUpdate(&mdctx, nonce, strlen(nonce));
  EVP_DigestUpdate(&mdctx, timeStamp, strlen(timeStamp));
  EVP_DigestUpdate(&mdctx, passWord.data(),passWord.size());
  EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
  EVP_MD_CTX_cleanup(&mdctx);
  char* digestStr=NULL;
  base64Encode(md_value,md_len,&digestStr);
  char* nonceBase64Str=NULL;
  base64Encode((const unsigned char*)nonce,strlen(nonce),&nonceBase64Str);
  std::string authStr=authFmtStr;
  authStr.replace(authStr.find(ARG_AUTH_USERNAME),sizeof(ARG_AUTH_USERNAME)-1,userName);
  authStr.replace(authStr.find(ARG_AUTH_NONCE),sizeof(ARG_AUTH_NONCE)-1,nonceBase64Str);
  authStr.replace(authStr.find(ARG_AUTH_TIMESTAMP),sizeof(ARG_AUTH_TIMESTAMP)-1,timeStamp);
  authStr.replace(authStr.find(ARG_AUTH_DIGEST),sizeof(ARG_AUTH_DIGEST)-1,digestStr);
  delete digestStr;
  return authStr;
}

std::string ONVIFUtil::unicastExcuteAction(std::string hostip,std::string port,std::string action)
{
  std::string respone;
  int ret=0;
  int socketHandle=socket(PF_INET,SOCK_STREAM,0);
  if(socketHandle<0)
  {
    std::cout<<"failed to create socket"<<std::endl;
    std::cout<<"err : "<<strerror(errno)<<std::endl;
    return respone;
  }

  struct timeval t;
  t.tv_sec=2;
  t.tv_usec=0;
  ret=setsockopt(socketHandle, SOL_SOCKET, SO_RCVTIMEO , &t ,sizeof(t));
  if(ret<0)
  {
    std::cout<<"failed to setsocketopt"<<std::endl;
    return respone;
  }

  struct sockaddr_in addr;
  memset(&addr,0,sizeof(addr));
  addr.sin_len=sizeof(struct sockaddr_in);
  addr.sin_port=htons(atoi(port.data()));
  addr.sin_addr.s_addr=inet_addr(hostip.data());
  connect(socketHandle,(const struct sockaddr*)&addr,sizeof(addr));

  std::string header=headerFmtStr;
  header.replace(header.find(ARG_HEADER_HOST),sizeof(ARG_HEADER_HOST)-1,hostip);
  char contentLengthStr[100];
  memset(contentLengthStr,0,100);
  sprintf(contentLengthStr,"%lu",action.size());
  header.replace(header.find(ARG_HEADER_CONTENT_LENGTH),sizeof(ARG_HEADER_CONTENT_LENGTH)-1,contentLengthStr);
  std::string request=header+action;
  ret=sendto(socketHandle,request.data(),request.size(),0,NULL,0);
  if(ret<0)
  {
    std::cout<<"failed to send"<<std::endl;
    std::cout<<"err : "<<strerror(errno)<<std::endl;
    return respone;
  }
  char buff[4096];
  while(1)
  {
    memset(buff,0,4096);
    ret=recvfrom(socketHandle,buff,4096,0,NULL,0);
    if(ret>0)
    {
      respone.append(buff,ret);
    }
    else
    {
      if(respone.size()==0)
      {
        std::cout<<"failed to recv"<<std::endl;
        std::cout<<"err : "<<strerror(errno)<<std::endl;
      }
      break;
    }
  }
  int responeCodeStart=respone.find(' ')+1;
  int responeCodeEnd=respone.find(' ',responeCodeStart);
  std::string responeCode=respone.substr(responeCodeStart,responeCodeEnd-responeCodeStart);
  if(responeCode!="200")
    respone.clear();
  close(socketHandle);
  return respone;
}

std::list<std::string> ONVIFUtil::multicastExcuteAction(std::string hostip,std::string port,std::string action)
{
  std::list<std::string> respones;
  int ret=0;
  int socketHandle=socket(PF_INET,SOCK_DGRAM,0);
  if(socketHandle<0)
  {
    return respones;
  }

  struct ip_mreq mreq;
  mreq.imr_multiaddr.s_addr = inet_addr(hostip.data());         
  mreq.imr_interface.s_addr = INADDR_ANY;         
  ret=setsockopt(socketHandle, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) ;
  if(ret<0)
  {
    std::cout<<"err : "<<strerror(errno)<<std::endl;
    return respones;
  }
  struct timeval t;
  t.tv_sec=2;
  t.tv_usec=0;
  ret=setsockopt(socketHandle, SOL_SOCKET, SO_RCVTIMEO , &t ,sizeof(t));
  if(ret<0)
  {
    std::cout<<"err : "<<strerror(errno)<<std::endl;
    return respones;
  }

  struct sockaddr_in addr;
  memset(&addr,0,sizeof(addr));
  addr.sin_len=sizeof(struct sockaddr_in);
  addr.sin_port=htons(atoi(port.data()));
  addr.sin_addr.s_addr=inet_addr(hostip.data());
  ret=sendto(socketHandle,action.data(),action.size(),0,(const struct sockaddr*)&addr,sizeof(addr));
  if(ret<0)
  {
    std::cout<<"err : "<<strerror(errno)<<std::endl;
    return respones;
  }
  char buff[4096];
  while(1)
  {
    memset(buff,0,4096);
    struct sockaddr_in peer;
    socklen_t len=sizeof(peer);
    ret=recvfrom(socketHandle,buff,4096,0,(struct sockaddr*)&peer,&len);
    if(ret>0)
    {
      std::string respone;
      respone.append(buff,ret);
      respones.push_back(respone);
    }
    else
      break;
  }
  return respones;
}

std::list<ONVIFUtil::XMLElement> ONVIFUtil::getElementValueByName(std::string xmlStr,std::string name)
{
  std::list<ONVIFUtil::XMLElement> elementS;
  std::list<NodeScope> scopeS=getNodeScope(xmlStr,name);
  for(std::list<NodeScope>::iterator scopeIter=scopeS.begin();scopeIter!=scopeS.end();scopeIter++)
  {
    XMLElement element;
    element.name=name; 
    std::string::size_type subNodePos=xmlStr.find('<',scopeIter->startElementEnd);
    if(subNodePos>=scopeIter->endElementStart || subNodePos==std::string::npos)
    {
      std::string value=xmlStr.substr(scopeIter->startElementEnd,scopeIter->endElementStart-scopeIter->startElementEnd);
      stripSpaceHeadAndTail(value);
      element.value=value;
    }
    std::string attrsStr=xmlStr.substr(scopeIter->startElementStart,scopeIter->startElementEnd-scopeIter->startElementStart);
    element.attrs=getAttrs(attrsStr);
    elementS.push_back(element);
  }
  return elementS;
}

std::list<std::string> ONVIFUtil::getElementValueByPath(std::string xmlStr,std::string path)
{
  std::list<std::string> values; 
  if(path.empty())
    return values;
  int pathNodeNameStart=0;
  int pathNodeNameEnd=0;
  std::list<std::string> pathNodes;
  do
  {
    pathNodeNameEnd=path.find("/",pathNodeNameStart);
    if(pathNodeNameEnd==std::string::npos)
      pathNodeNameEnd=path.size();
    std::string pathNodeName=path.substr(pathNodeNameStart,pathNodeNameEnd-pathNodeNameStart);
    pathNodes.push_front(pathNodeName);
    pathNodeNameStart=pathNodeNameEnd+1;
  }
  while((pathNodeNameEnd=path.find("/",pathNodeNameStart))!=std::string::npos);

  int elementStart=0;
  int elementEnd=0;

  while((elementStart=xmlStr.find(*pathNodes.begin(),elementEnd))!=std::string::npos)
  {
    for(std::list<std::string>::iterator nodeIter=pathNodes.begin();nodeIter!=pathNodes.end();nodeIter++)
    {
      elementStart=xmlStr.find(*nodeIter,elementStart);  
    }
  }
  return values;
}

