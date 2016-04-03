#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h>
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h> 

int count = 1; 
void packets(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet){  // функция обработки пакетов (аргументы, размеры пакета, пакет)
  printf("%3d, ", count);
  fflush(stdout);
  count++; 
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
    perror("pcap_open_live()");
    return -1;
  } 

  // составляем фильтр из строки в составной вид
  if(pcap_compile(descr, &fp, "ip", 0, netp) == -1){ 
    perror("pcap_mcompile()");
    return -1;
  } 
  // применяем фильтр
  if(pcap_setfilter(descr, &fp) == -1) {
    perror("pcap_setfilter");
    return -1;
  } 
  // запускаем цикл для обработки пакетов
  pcap_loop(descr, -1, packets, NULL); 
  return 0; 
}
