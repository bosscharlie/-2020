#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <vector>
#include <iostream>
#include <algorithm>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool prefix_query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern std::vector<RoutingTableEntry> lineartable;

uint8_t packet[2048];
uint8_t output[2048];

// for online experiment, don't change
#ifdef ROUTER_R1
// 0: 192.168.1.1
// 1: 192.168.3.1
// 2: 192.168.6.1
// 3: 192.168.7.1
const in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0101a8c0, 0x0103a8c0, 0x0106a8c0,
                                           0x0107a8c0};
#elif defined(ROUTER_R2)
// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 192.168.8.1
// 3: 192.168.9.1
const in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0108a8c0,
                                           0x0109a8c0};
#elif defined(ROUTER_R3)
// 0: 192.168.4.2
// 1: 192.168.5.2
// 2: 192.168.10.1
// 3: 192.168.11.1
const in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0204a8c0, 0x0205a8c0, 0x010aa8c0,
                                           0x010ba8c0};
#else
// 自己调试用，你可以按需进行修改，注意字节序
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a,
                                     0x0103000a};
#endif

typedef struct finder_t
{
    finder_t(uint32_t dstaddr,uint32_t dstmask) : addr(dstaddr),mask(dstmask) { } 
    bool operator()(RoutingTableEntry p) 
    { 
        return (mask==p.mask)&&(addr&mask == p.addr&p.mask); 
    } 
    uint32_t addr;
    uint32_t mask;
}finder_t;

uint32_t masktolen(uint32_t mask){
  uint32_t cnt=0;
  while (mask>0)
  {
    cnt++;
    mask>>1;
  }
  return cnt;
}

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00FFFFFF, // network byte order
        .len = 24,                     // host byte order
        .if_index = i,                 // host byte order
        .nexthop = 0,                   // network byte order, means direct
        .metric = 1,
        .mask = (1<<24)-1
    };
    update(true, entry);
  }
  printf("start\n");
  fflush(stdout);
  for(int i=0;i<lineartable.size();i++){
    printf("%x\n",lineartable[i].addr);
    fflush(stdout);
  }
  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    // the RFC says 30s interval,
    // but for faster convergence, use 5s here
    if (time > last_time + 5 * 1000) {
      // ref. RFC 2453 Section 3.8
      printf("5s Timer\n");
      fflush(stdout);
      // HINT: print complete routing table to stdout/stderr for debugging
      // TODO: send complete routing table to every interface
      for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
        // construct rip response
        // do the mostly same thing as step 3a.3
        // except that dst_ip is RIP multicast IP 224.0.0.9
        // and dst_mac is RIP multicast MAC 01:00:5e:00:00:09
        macaddr_t bmac;
        bmac[0]=1;
        bmac[1]=0;
        bmac[2]=94;
        bmac[3]=0;
        bmac[4]=0;
        bmac[5]=9;
        RipPacket resp;
        resp.command=2;
        resp.numEntries=htonl(0);
        uint32_t rip_len;
        int count=0;
        for(int i=0;i<lineartable.size();i++){
          resp.entries[i%25] = {
            .addr=lineartable[i].addr,
            .mask=lineartable[i].mask,
            .nexthop=lineartable[i].nexthop,
            .metric=lineartable[i].metric
          };
          printf("%x\n",resp.entries[i%25].addr);
          fflush(stdout);
          resp.numEntries=resp.numEntries+htonl(1);
          count++;
          // fill IP headers
          struct ip *ip_header = (struct ip *)output;
          ip_header->ip_hl = htonl(5);
          ip_header->ip_v = htonl(4);
          // TODO: set tos = 0, id = 0, off = 0, ttl = 1, p = 17(udp), dst and src
          ip_header->ip_tos=0;
          ip_header->ip_id=0;
          ip_header->ip_off=0;
          ip_header->ip_ttl=1;
          ip_header->ip_p=17;
          ip_header->ip_dst.s_addr=htonl((in_addr_t)((224<<24)+9));
          ip_header->ip_src.s_addr=htonl(addrs[i]);
          // fill UDP headers
          struct udphdr *udpHeader = (struct udphdr *)&output[20];
          // src port = 520
          udpHeader->uh_sport = htons(520);
          // dst port = 520
          udpHeader->uh_dport = htons(520);
          // TODO: udp length
          udpHeader->len = htons((uint16_t)32);
          // assemble RIP
          rip_len = assemble(&resp, &output[20 + 8]);

          // TODO: checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          ip_header->ip_sum=0;
          uint8_t *ippacket=(uint8_t*)ip_header;
          int ans=0;
          ans=0;
          for(int i=0;i<ip_header->ip_len;i=i+2){
            ans+=(int)(ippacket[i]*256+ippacket[i+1]);
          }
          while(ans>65535){
            int temp=ans/65536; 
            ans=ans%65536;
            ans=ans+temp;
          }
          ans=(~ans)&65535;
          ip_header->ip_sum=htons((uint16_t)ans);
          udpHeader->uh_sum=0;
          // send it back
          if(count==25){
            //(macaddr_t){(uint8_t)1,(uint8_t)0,(uint8_t)94,(uint8_t)0,(uint8_t)0,(uint8_t)9}
            HAL_SendIPPacket(i, output, rip_len + 20 + 8, bmac);
            count=0;
            resp.numEntries=htonl(0);
          }
        }
        if(count!=0)
          HAL_SendIPPacket(i, output, rip_len + 20 + 8, bmac);
      }
      last_time = time;
    }
    printf("end timer");
    fflush(stdout);
    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    printf("receive success");
    fflush(stdout);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      // drop if ip checksum invalid
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // TODO: extract src_addr and dst_addr from packet (big endian)
    struct ip *ippacket=(struct ip*)packet;
    src_addr=ippacket->ip_src.s_addr;
    dst_addr=ippacket->ip_dst.s_addr;
    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: handle rip multicast address(224.0.0.9)

    if (dst_is_me) {
      // 3a.1
      printf("dst is me\n");
      fflush(stdout);
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC 2453 Section 3.9.1
          // only need to respond to whole table requests in the lab

          RipPacket resp;
          // TODO: fill resp
          // implement split horizon with poisoned reverse
          // ref. RFC 2453 Section 3.4.3
          resp.command=2;
          resp.numEntries=htonl(0);
          uint32_t rip_len;
          int count=0;
          for(int i=0;i<lineartable.size();i++){
            resp.entries[i%25] = {
              .addr=lineartable[i].addr,
              .mask=lineartable[i].mask,
              .nexthop=lineartable[i].nexthop,
              .metric=(if_index==i)?htonl((uint32_t)16):lineartable[i].metric
            };
            resp.numEntries=resp.numEntries+htonl(1);
            count++;
            // fill IP headers
            struct ip *ip_header = (struct ip *)output;
            ip_header->ip_hl = 0;
            ip_header->ip_v = htonl(4);
            // TODO: set tos = 0, id = 0, off = 0, ttl = 1, p = 17(udp), dst and src
            ip_header->ip_tos=0;
            ip_header->ip_id=0;
            ip_header->ip_off=0;
            ip_header->ip_ttl=1;
            ip_header->ip_p=17;
            ip_header->ip_dst.s_addr=src_addr;
            ip_header->ip_src.s_addr=dst_addr;
            // fill UDP headers
            struct udphdr *udpHeader = (struct udphdr *)&output[20];
            // src port = 520
            udpHeader->uh_sport = htons(520);
            // dst port = 520
            udpHeader->uh_dport = htons(520);
            // TODO: udp length
            udpHeader->len = htons((uint16_t)32);
            // assemble RIP
            rip_len = assemble(&resp, &output[20 + 8]);

            // TODO: checksum calculation for ip and udp
            // if you don't want to calculate udp checksum, set it to zero
            udpHeader->uh_sum=0;
            ip_header->ip_sum=0;
            uint8_t *ippacket=(uint8_t*)ip_header;
            int ans=0;
            ans=0;
            for(int i=0;i<ip_header->ip_len;i=i+2){
              ans+=(int)(ippacket[i]*256+ippacket[i+1]);
            }
            while(ans>65535){
              int temp=ans/65536; 
              ans=ans%65536;
              ans=ans+temp;
            }
            ans=(~ans)&65535;
            ip_header->ip_sum=htons((uint16_t)ans);
            // send it back
            if(count==25){
              HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
              count=0;
              resp.numEntries=htonl(0);
            }
          }
          if(count!=0)
            HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          printf("response rip\n");
          fflush(stdout);
          // 3a.2 response, ref. RFC 2453 Section 3.9.2
          // TODO: update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // HINT: handle nexthop = 0 case
          // HINT: what is missing from RoutingTableEntry?
          // you might want to use `prefix_query` and `update`, but beware of
          // the difference between exact match and longest prefix match.
          // optional: triggered updates ref. RFC 2453 Section 3.10.1
          for(int i=0;i<rip.numEntries;i++){
              auto it = std::find_if(lineartable.begin(),lineartable.end(),finder_t(rip.entries[i].addr,rip.entries[i].mask));
              RoutingTableEntry insertentry;
              insertentry.addr=rip.entries[i].addr;
              insertentry.mask=rip.entries[i].mask;
              insertentry.metric=ntohl(rip.entries[i].metric)+1<(uint32_t)16?rip.entries[i].metric+htonl(1):htonl((uint32_t)16);
              insertentry.nexthop=rip.entries[i].nexthop;
              insertentry.if_index=if_index;
              insertentry.len=masktolen(ntohl(rip.entries[i].mask)+1);
              if(it!=lineartable.end()){
                if(it->nexthop==src_addr){
                  if(ntohl(rip.entries[i].metric)==(uint32_t)16){ //poison reverse
                    update(false,insertentry);
                  }else if(rip.entries[i].metric<it->metric){
                    it->metric=rip.entries[i].metric+htonl(1);
                    it->nexthop=src_addr;
                    it->if_index=if_index;
                  }
                }
              }else{
                update(true,insertentry);
              }
          }
        }
      } else {
        printf("not rip packet\n");
        fflush(stdout);
        // not a rip packet
        // handle icmp echo request packet
        // TODO: how to determine?
        struct ip *ip_header = (struct ip *)packet;
        if (ip_header->ip_p==1) {
          struct icmphdr *icmp_header=(struct icmphdr *)&packet[20];
          // construct icmp echo reply
          // reply is mostly the same as request,
          // you need to:
          // 1. swap src ip addr and dst ip addr
          // 2. change icmp `type` in header
          // 3. set ttl to 64
          // 4. re-calculate icmp checksum and ip checksum
          // 5. send icmp packet
          if(icmp_header->type==8){
            printf("icmp\n");
            fflush(stdout);
            ip_header=(struct ip *)output;
            icmp_header=(struct icmphdr *)&output[20];
            ip_header->ip_src.s_addr=dst_addr;
            ip_header->ip_src.s_addr=src_addr;
            icmp_header->type=0;
            ip_header->ip_ttl=(uint8_t)64;
            ip_header->ip_sum=0;
            icmp_header->checksum=0;
            uint8_t *ippacket=(uint8_t*)ip_header;
            int ans=0;
            for(int i=0;i<ip_header->ip_len;i=i+2){
              ans+=(int)(ippacket[i]*256+ippacket[i+1]);
            }
            while(ans>65535){
              int temp=ans/65536; 
              ans=ans%65536;
              ans=ans+temp;
            }
            ans=(~ans)&65535;
            ip_header->ip_sum=htons((uint16_t)ans);
            uint8_t *icmppacket=(uint8_t*)icmp_header;
            ans=0;
            for(int i=0;i<8;i=i+2){
              ans+=(int)(icmppacket[i]*256+icmppacket[i+1]);
            }
            while(ans>65535){
              int temp=ans/65536; 
              ans=ans%65536;
              ans=ans+temp;
            }
            ans=(~ans)&65535;
            icmp_header->checksum=htons((uint16_t)ans);
            HAL_SendIPPacket(if_index, output, 28, src_mac);
          }
        }
      }
    } else {
      printf("dst is not me\n");
      fflush(stdout);
      // 3b.1 dst is not me
      // check ttl
      uint8_t ttl = packet[8];
      if (ttl <= 1) {
        // send icmp time to live exceeded to src addr
        // fill IP header
        struct ip *ip_header = (struct ip *)output;
        ip_header->ip_hl = htonl(5);
        ip_header->ip_v = htonl(4);
        // TODO: set tos = 0, id = 0, off = 0, ttl = 64, p = 1(icmp), src and dst
        ip_header->ip_tos=0;
        ip_header->ip_id=0;
        ip_header->ip_off=0;
        ip_header->ip_ttl=64;
        ip_header->ip_p=1;
        ip_header->ip_src.s_addr=dst_addr;
        ip_header->ip_dst.s_addr=src_addr;
        // fill icmp header
        struct icmphdr *icmp_header = (struct icmphdr *)&output[20];
        // icmp type = Time Exceeded
        icmp_header->type = ICMP_TIME_EXCEEDED;
        // TODO: icmp code = 0
        icmp_header->code=0;
        // TODO: fill unused fields with zero
        icmp_header->un.gateway=0;
        icmp_header->un.echo.id=0;
        icmp_header->un.echo.sequence=0;
        icmp_header->un.frag.mtu=0;
        icmp_header->un.frag.__glibc_reserved=0;
        // TODO: append "ip header and first 8 bytes of the original payload"
        memcpy(&output[28],packet,28*sizeof(uint8_t));
        // TODO: calculate icmp checksum and ip checksum
        uint8_t *ippacket=(uint8_t*)ip_header;
        int ans=0;
        for(int i=0;i<ip_header->ip_len;i=i+2){
          ans+=(int)(ippacket[i]*256+ippacket[i+1]);
        }
        while(ans>65535){
          int temp=ans/65536; 
          ans=ans%65536;
          ans=ans+temp;
        }
        ans=(~ans)&65535;
        ip_header->ip_sum=htons((uint16_t)ans);
        uint8_t *icmppacket=(uint8_t*)icmp_header;
        ans=0;
        for(int i=0;i<8;i=i+2){
          ans+=(int)(icmppacket[i]*256+icmppacket[i+1]);
        }
        while(ans>65535){
          int temp=ans/65536; 
          ans=ans%65536;
          ans=ans+temp;
        }
        ans=(~ans)&65535;
        icmp_header->checksum=htons((uint16_t)ans);
        // TODO: send icmp packet
        HAL_SendIPPacket(if_index, output, 56, src_mac);
      } else {
        printf("forward\n");
        fflush(stdout);
        // forward
        // beware of endianness
        uint32_t nexthop, dest_if;
        if (prefix_query(dst_addr, &nexthop, &dest_if)) {
          // found
          macaddr_t dest_mac;
          // direct routing
          if (nexthop == 0) {
            nexthop = dst_addr;
          }
          if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
            // found
            memcpy(output, packet, res);
            // update ttl and checksum
            forward(output, res);
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          } else {
            // not found
            // you can drop it
            printf("ARP not found for nexthop %x\n", nexthop);
          }
        } else {
          // not found
          // send ICMP Destination Network Unreachable
          printf("IP not found in routing table for src %x dst %x\n", src_addr, dst_addr);
          // send icmp destination net unreachable to src addr
          // fill IP header
          struct ip *ip_header = (struct ip *)output;
          ip_header->ip_hl = 5;
          ip_header->ip_v = 4;
          // TODO: set tos = 0, id = 0, off = 0, ttl = 64, p = 1(icmp), src and dst
          ip_header->ip_tos=0;
          ip_header->ip_id=0;
          ip_header->ip_off=0;
          ip_header->ip_ttl=64;
          ip_header->ip_p=1;
          ip_header->ip_src.s_addr=dst_addr;
          ip_header->ip_dst.s_addr=src_addr;
          // fill icmp header
          struct icmphdr *icmp_header = (struct icmphdr *)&output[20];
          // icmp type = Destination Unreachable
          icmp_header->type = ICMP_DEST_UNREACH;
          // TODO: icmp code = Destination Network Unreachable
          icmp_header->code = ICMP_DEST_UNREACH;
          // TODO: fill unused fields with zero
          icmp_header->un.gateway=0;
          icmp_header->un.echo.id=0;
          icmp_header->un.echo.sequence=0;
          icmp_header->un.frag.mtu=0;
          icmp_header->un.frag.__glibc_reserved=0;
          // TODO: append "ip header and first 8 bytes of the original payload"
          memcpy(&output[28],packet,28*sizeof(uint8_t));
          // TODO: calculate icmp checksum and ip checksum
          uint8_t *ippacket=(uint8_t*)ip_header;
          int ans=0;
          for(int i=0;i<ip_header->ip_len;i=i+2){
            ans+=(int)(ippacket[i]*256+ippacket[i+1]);
          }
          while(ans>65535){
            int temp=ans/65536; 
            ans=ans%65536;
            ans=ans+temp;
          }
          ans=(~ans)&65535;
          ip_header->ip_sum=htons((uint16_t)ans);
          uint8_t *icmppacket=(uint8_t*)icmp_header;
          ans=0;
          for(int i=0;i<8;i=i+2){
            ans+=(int)(icmppacket[i]*256+icmppacket[i+1]);
          }
          while(ans>65535){
            int temp=ans/65536; 
            ans=ans%65536;
            ans=ans+temp;
          }
          ans=(~ans)&65535;
          icmp_header->checksum=htons((uint16_t)ans);
          // TODO: send icmp packet
          HAL_SendIPPacket(if_index, output, 56, src_mac);
        }
      }
    }
  }
  return 0;
}
