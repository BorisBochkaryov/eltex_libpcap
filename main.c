#include <stdio.h> 
#include <stdlib.h>
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h> 
#include <netinet/ether.h> 
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <pcap.h> 

/*struct ether_header { // L2 // из файла /usr/include/net/ethernet.h
  char ether_dhost[ETHER_ADDR_LEN]; // MAC получателя
  char ether_shost[ETHER_ADDR_LEN]; // MAC отправителя
  short ether_type;   // тип протокола
};*/

/* struct pcap_pkthdr {
 * struct timeval ts; // время перехвала
 * int32 caplen; // длина фрагмента
 * int32 len; // длина пакета
 */
 
struct my_ip { // L3 (IP пакет) // url http://iptcp.net/sites/default/files/15/1.JPG
  u_int8_t ip_vhl; // версия протокола
#define IP_V(ip)  (((ip)->ip_vhl & 0xf0) >> 4) // для определения длины заголовка
#define IP_HL(ip)  ((ip)->ip_vhl & 0x0f)
  u_int8_t ip_tos;  // тип сервиса
  u_int16_t ip_len; // длина пакета
  u_int16_t ip_id;  // идентификатор пакета
  u_int16_t ip_off; // смещение фрагмента
  /* флаги */
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x01fff
  u_int8_t ip_ttl; // время жизни
  u_int8_t ip_p; // протокол
  u_int16_t ip_sum;  // контрольная сумма
  struct in_addr ip_src, ip_dst; // ip источника и назначения
};  
 
void handle_tcp(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet, u_int16_t len){ // распарсивание TCP пакета
  struct tcphdr* tcp;
  u_char *data;
  int iplen=sizeof(struct ether_header)+sizeof(struct my_ip);
  int tcplen=iplen+sizeof(struct tcphdr);
    
  tcp=(struct tcphdr *)(packet+iplen); // получает tcp с необходимого места
  /* выводим необходимую информацию */
  printf("TCP\nsource port: %d", ntohs(tcp->th_sport)); 
  printf(" dest port: %d\n\n", ntohs(tcp->th_dport));
} 
 
u_short handle_ethernet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet){ // получение L2 данных
  struct ether_header *eth;
  eth=(struct ether_header *)packet;
  printf("L2\nsource: %s", ether_ntoa(eth->ether_shost));
  printf(" dest: %s\n", ether_ntoa(eth->ether_dhost));
  return ntohs(eth->ether_type);
}
 
void handle_ip(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet){ // получение L3 данных
  const struct my_ip* ip;
 
  ip=(struct my_ip *)(packet+sizeof(struct ether_header));
  printf("L3\nsource: %s ", inet_ntoa(ip->ip_src));
  printf("dest: %s\n", inet_ntoa(ip->ip_dst));
  printf("\ttos: %d len: %d id: %d ttl: %d\n", ip->ip_tos, ip->ip_len, 
      ip->ip_id, ip->ip_ttl);
  if(ip->ip_p == IPPROTO_TCP) handle_tcp(args, pkthdr, packet, ip->ip_len);
  else printf("\n");
}
 
void packets(u_char *args, const struct pcap_pkthdr* pkthdr, u_char* packet){  // функция обработки пакетов (аргументы, размеры пакета, пакет)
  u_int16_t etype=handle_ethernet(args, pkthdr, packet);
  if(etype==ETHERTYPE_IP) { handle_ip(args, pkthdr, packet); }
}

int main(){ 
  char *dev; 
  char errbuf[255]; 
  pcap_t* descr; 
  struct bpf_program fp;     // фильтр в составном виде 
  bpf_u_int32 netp;          // ip 
  bpf_u_int32 maskp;         // маска подсети
  
  // Получение имени устройства
  if((dev = pcap_lookupdev(errbuf)) == NULL){
    perror("Error pcap_lookupdev()");
    return -1;
  } 
  // Получение IPv4 информации об устройстве
  pcap_lookupnet(dev, &netp, &maskp, errbuf); 

  // открыть устройство (неразборчивый режим третий слева параметр)  
  if((descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf)) == NULL){
    perror("Error pcap_open_live()");
    return -1;
  } 
  
  // запускаем цикл для обработки пакетов
  pcap_loop(descr, -1, packets, NULL); 
  return 0; 
}
