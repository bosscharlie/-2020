#include <stdint.h>
#include <stdlib.h>
// 在 checksum.cpp 中定义
extern bool validateIPChecksum(uint8_t *packet, size_t len);

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以调用 checksum 题中的 validateIPChecksum 函数，
 *        编译的时候会链接进来。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  // TODO:
  int ans=0;
  int size=(int)(packet[0]%16)*4;
  for(int i=0;i<size;i=i+2){
    ans+=(int)(packet[i]*256+packet[i+1]);
  }
  while(ans>65535){
    int temp=ans/65536; 
    ans=ans%65536;
    ans=ans+temp;
  }
  if(ans!=65535)
    return false;
  int ttl=(int)packet[8];
  ttl=ttl-1;
  packet[8]=(uint8_t)(ttl);
  packet[10]=(uint8_t)0;
  packet[11]=(uint8_t)0;
  ans=0;
  for(int i=0;i<size;i=i+2){
    ans+=(int)(packet[i]*256+packet[i+1]);
  }
  while(ans>65535){
    int temp=ans/65536; 
    ans=ans%65536;
    ans=ans+temp;
  }
  ans=(~ans)&65535;
  packet[10]=(uint8_t)(ans/256);
  packet[11]=(uint8_t)(ans%256);
  return true;
}