#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include<iostream>
#include <arpa/inet.h>
using namespace std;
/*
  在头文件 rip.h 中定义了结构体 `RipEntry` 和 `RipPacket` 。
  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的
  IP 包。 由于 RIP 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在
  RipPacket 中额外记录了个数。 需要注意这里的地址都是用 **网络字节序（大端序）**
  存储的，1.2.3.4 在小端序的机器上被解释为整数 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 RIP 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回
 * true；否则返回 false
 *
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len
 * 时，把传入的 IP 包视为不合法。 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  int totallen=(int)packet[2]*256+(int)packet[3];
  if(totallen>(int)len)
    return false;
  int command=(int)packet[28];
  if(command!=1&&command!=2)
    return false;
  int version=(int)packet[29];
  if(version!=2)
    return false;
  int zero=(int)packet[30]*256+packet[31];
  if(zero!=0)
    return false;
  int family=(int)packet[32]*256+packet[33];
  if(!((command==1&&family==0)||(command==2&&family==2)))
    return false;
  int tag=(int)packet[34]*256+packet[35];
  if(tag!=0)
    return false;
  int riplen=((int)len-32)/20;
  output->numEntries=(uint32_t)riplen;
  output->command=packet[28];
  int count=0;
  for(int i=32;i<(int)len;i=i+20){
    output->entries[count].addr=htonl((((uint32_t)packet[i+4])<<24)+(((uint32_t)packet[i+5])<<16)+(((uint32_t)packet[i+6])<<8)+(((uint32_t)packet[i+7])));
    //printf("%x\n",(output->entries[count].addr));
    //printf("%x\n",((uint8_t*)&output->entries[count].addr)[3]);
    //printf("%x\n",((uint8_t)output->entries[count].addr));
    //printf("%x\n",((uint8_t)output->entries[count].addr));
    output->entries[count].mask=htonl((((uint32_t)packet[i+8])<<24)+(((uint32_t)packet[i+9])<<16)+(((uint32_t)packet[i+10])<<8)+(((uint32_t)packet[i+11])));
    output->entries[count].nexthop=htonl((((uint32_t)packet[i+12])<<24)+(((uint32_t)packet[i+13])<<16)+(((uint32_t)packet[i+14])<<8)+(((uint32_t)packet[i+15])));
    //TODO judge nextmask
    uint32_t metric=(((uint32_t)packet[i+16])<<24)+(((uint32_t)packet[i+17])<<16)+(((uint32_t)packet[i+18])<<8)+(((uint32_t)packet[i+19]));
    if((int)metric<1||(int)metric>16)
      return false;
    output->entries[count].metric=htonl(metric);
    count++;
  }
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 *
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括
 * Version、Zero、Address Family 和 Route Tag 这四个字段 你写入 buffer
 * 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  buffer[0]=rip->command;
  buffer[1]=(uint8_t)2;
  buffer[2]=(uint8_t)0;
  buffer[3]=(uint8_t)0;
  int len=4;
  uint32_t family;
  if((int)rip->command==1)
    family=(uint8_t)0;
  else if((int)rip->command==2)
    family=(uint8_t)2;
  for(int i=0;i<rip->numEntries;i++){
    buffer[4+20*i]=(uint8_t)0;
    buffer[5+20*i]=family;
    buffer[6+20*i]=(uint8_t)0;
    buffer[7+20*i]=(uint8_t)0;
    buffer[8+20*i]=((uint8_t*)&rip->entries[i].addr)[0];
    buffer[9+20*i]=((uint8_t*)&rip->entries[i].addr)[1];
    buffer[10+20*i]=((uint8_t*)&rip->entries[i].addr)[2];
    buffer[11+20*i]=((uint8_t*)&rip->entries[i].addr)[3];
    buffer[12+20*i]=((uint8_t*)&rip->entries[i].mask)[0];
    buffer[13+20*i]=((uint8_t*)&rip->entries[i].mask)[1];
    buffer[14+20*i]=((uint8_t*)&rip->entries[i].mask)[2];
    buffer[15+20*i]=((uint8_t*)&rip->entries[i].mask)[3];
    buffer[16+20*i]=((uint8_t*)&rip->entries[i].nexthop)[0];
    buffer[17+20*i]=((uint8_t*)&rip->entries[i].nexthop)[1];
    buffer[18+20*i]=((uint8_t*)&rip->entries[i].nexthop)[2];
    buffer[19+20*i]=((uint8_t*)&rip->entries[i].nexthop)[3];
    buffer[20+20*i]=((uint8_t*)&rip->entries[i].metric)[0];
    buffer[21+20*i]=((uint8_t*)&rip->entries[i].metric)[1];
    buffer[22+20*i]=((uint8_t*)&rip->entries[i].metric)[2];
    buffer[23+20*i]=((uint8_t*)&rip->entries[i].metric)[3];
    len=len+20;
  }
  return len;
}
