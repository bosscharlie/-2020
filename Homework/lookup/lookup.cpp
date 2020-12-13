#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <arpa/inet.h>
std::vector<RoutingTableEntry> lineartable;
/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 *
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len **精确** 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  if(insert){
    bool exist=false;
    for(int i=0;i<lineartable.size();i++){
      if(lineartable[i].addr==entry.addr&&lineartable[i].len==entry.len){
        lineartable[i]=entry;
        exist=true;
      }
    }
    if(!exist)
      lineartable.push_back(entry);
  }else{
    for(int i=0;i<lineartable.size();i++){
      if(lineartable[i].addr==entry.addr&&lineartable[i].len==entry.len){
        lineartable.erase(lineartable.begin()+i);
        break;
      }
    }
  }
  // TODO:
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，网络字节序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool prefix_query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
  *nexthop = 0;
  *if_index = 0;
  RoutingTableEntry* temp=NULL;
  int templen=0;
  for(int i=0;i<lineartable.size();i++){
    if(lineartable[i].len==0&&(int)lineartable[i].len>=templen){
      templen=lineartable[i].len;
      temp=&lineartable[i];
    }
    else if(ntohl(lineartable[i].addr)>>(32-(int)lineartable[i].len)==ntohl(addr)>>(32-(int)lineartable[i].len)&&(int)lineartable[i].len>=templen){
      templen=lineartable[i].len;
      temp=&lineartable[i];
    }
  }
  if(temp!=NULL){
    *nexthop=temp->nexthop;
    *if_index=temp->if_index;
    return true;
  }
  return false;
}
