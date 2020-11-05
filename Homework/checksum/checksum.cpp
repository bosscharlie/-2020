#include <stdint.h>
#include <stdlib.h>
/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
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
  if(ans==65535)
    return true;
  else
    return false;
}
