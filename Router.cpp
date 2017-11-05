#include <vector>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/if_ether.h>

//#include <net/if_dl.h>
#include <netpacket/packet.h>
#include <string.h>
//#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
//#include <thread>
#include <map>


class Router {
  
    private:
    
    //map pointers to the iterfaces to the socket numbers they are bound to
      std::map<struct ifaddrs*, int> socketMap;

      std::vector<struct ifaddrs> interfaces;
      std::vector<int> sockets;

    //keep the initial linked list around
       struct ifaddrs *ifaddr;
    
    //std::vector<std::string[]> routingTable;
    
    public:
    Router(){
        
        int packet_socket;
        //get list of interfaces (actually addresses)
        struct ifaddrs *tmp;
        struct sockaddr_ll *mymac;
        
        if(getifaddrs(&ifaddr)==-1){
            perror("getifaddrs");
        }
        
        for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){
            
            //Check if this is a packet address, there will be one per
            //interface.  There are IPv4 and IPv6 as well, but we don't care
            //about those for the purpose of enumerating interfaces. We can
            //use the AF_INET addresses in this list for example to get a list
            //of our own IP addresses
            if(tmp->ifa_addr->sa_family==AF_PACKET){
                printf("found socket address\n");
                printf("name: %s \n", tmp->ifa_name);
                printf("family: %u \n", tmp->ifa_addr->sa_family);
                
                //create a packet socket on interface r?-eth1
                interfaces.push_back(*tmp);
               
                printf("Creating Socket on interface %s",tmp->ifa_name);
                
                //create a packet socket
                //AF_PACKET makes it a packet socket
                //SOCK_RAW makes it so we get the entire packet
                //could also use SOCK_DGRAM to cut off link layer header
                //ETH_P_ALL indicates we want all (upper layer) protocols
                //we could specify just a specific one
                packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
                socketMap.insert(std::pair<struct ifaddrs*, int>(tmp, packet_socket));
                
//                unsigned char *ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)(tmp->ifa_addr));
//                printf(": %02x:%02x:%02x:%02x:%02x:%02x\n\n",
//                       *ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));
                
                mymac  = (struct sockaddr_ll*)tmp->ifa_addr;
//                printf("Our Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",mymac->sll_addr[0],mymac->sll_addr[1],mymac->sll_addr[2],mymac->sll_addr[3],mymac->sll_addr[4],mymac->sll_addr[5]);

                sockets.push_back(packet_socket);
                //packet_socket->sockaddr_ll;
                if(packet_socket<0){
                    perror("socket");
                   
                }
                //Bind the socket to the address, so we only get packets
                //recieved on this specific interface. For packet sockets, the
                //address structure is a struct sockaddr_ll (see the man page
                //for "packet"), but of course bind takes a struct sockaddr.
                //Here, we can use the sockaddr we got from getifaddrs (which
                //we could convert to sockaddr_ll if we needed to)
                
                if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
                        perror("bind");
                    }
                
                
    
               
                
                //struct ether_header *etherH = (struct ether_header*)(buf);
                //struct ether_arp *arpH = (struct ether_arp*)(buf);
                
              
            }
            
            
        }
    }
    
    char * response(char buf[]){
    
        struct ether_header *etherH = (struct ether_header*)(buf);
        //struct ether_arp *arpH = (struct ether_arp*)(buf+14);
    
        //printf("%lu\n", sizeof(struct ether_header));
    
        // buildResponse(eth0, etherH, arpH);
        printf("+++++++++++++++Recieving Info+++++++++++++++\n");
        printf("Sender Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", etherH->ether_shost[0], etherH->ether_shost[1],
               etherH->ether_shost[2], etherH->ether_shost[3], etherH->ether_shost[4], etherH->ether_shost[5]);
        //printf("%d\n", arpH->arp_op);
        printf("type: %x\n",ntohs(etherH->ether_type));
        if(ntohs(etherH->ether_type)==ETHERTYPE_ARP){
            struct ether_arp *arpH = (struct ether_arp*)(buf+14);
            printf("hardware: %x\n", ntohs(arpH->arp_hrd));
            printf("protocol: %x\n", ntohs(arpH->arp_pro));
            printf("hlen: %x\n", arpH->arp_hln);
            printf("plen: %x\n", arpH->arp_pln);
            printf("arp op: %x\n", ntohs(arpH->arp_op));
            printf("sender mac: %02x:%02x:%02x:%02x:%02x:%02x\n", arpH->arp_sha[0], arpH->arp_sha[1],
                   arpH->arp_sha[2], arpH->arp_sha[3], arpH->arp_sha[4], arpH->arp_sha[5]);
            printf("sender IP: %02d:%02d:%02d:%02d\n", arpH->arp_spa[0], arpH->arp_spa[1],
                   arpH->arp_spa[2], arpH->arp_spa[3]);
            printf("Target IP: %02d:%02d:%02d:%02d\n", arpH->arp_tpa[0], arpH->arp_tpa[1],
                   arpH->arp_tpa[2], arpH->arp_tpa[3]);
    
    
            printf("sender protoc: %d\n", arpH->arp_spa[0]);
            //arpResp->arp_tha[0] = arpH->arp_sha;
            //arpResp->arp_tpa = arpH->arp_spa;
            //arpResp->arp_spa = arpH->arp_tpa;
            //arpResp->arp_sha = //my mac
    
            char replyBuffer[42];
            
            struct ether_header *outEther = (struct ether_header *)(replyBuffer);
            struct ether_arp *arpResp = (struct ether_arp *)(replyBuffer+14);
            memcpy(outEther->ether_dhost, etherH->ether_shost,6);
            //memcpy(outEther->ether_shost, mymac->sll_addr,6);
            outEther->ether_type = 1544;
            printf("-------------------------------Sending Info-----------------------\n");
            printf("ETHER HEADER:_________________________\n");
            printf("My Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", outEther->ether_shost[0], outEther->ether_shost[1],
                   outEther->ether_shost[2], outEther->ether_shost[3], outEther->ether_shost[4], outEther->ether_shost[5]);
    
            printf("Dest Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", outEther->ether_dhost[0], outEther->ether_dhost[1],
                   outEther->ether_dhost[2], outEther->ether_dhost[3], outEther->ether_dhost[4], outEther->ether_dhost[5]);
    
            printf("Protocol: %x\n",outEther->ether_type);
    
            arpResp->ea_hdr.ar_hrd = 0x100;
            arpResp->ea_hdr.ar_pro = 0x8;
            arpResp->ea_hdr.ar_hln = 0x6;
            arpResp->ea_hdr.ar_pln = 0x4;
            arpResp->ea_hdr.ar_op = htons(0x2);
            memcpy(arpResp->arp_tha,arpH->arp_sha,6);
            memcpy(arpResp->arp_tpa,arpH->arp_spa,4);
            memcpy(arpResp->arp_sha,outEther->ether_shost,6);
            memcpy(arpResp->arp_spa,arpH->arp_tpa,4);
    
            printf("ARPRESP HEADER:__________________\n");
    
            printf("Hardware: %x\n", ntohs(arpResp->arp_hrd));
            printf("Protocol: %x\n", ntohs(arpResp->arp_pro));
            printf("Hlen: %x\n", arpResp->arp_hln);
            printf("Plen: %x\n", arpResp->arp_pln);
            printf("Arp Op: %x\n", ntohs(arpResp->arp_op));
            printf("Sender Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", arpResp->arp_sha[0], arpResp->arp_sha[1],
                   arpResp->arp_sha[2], arpResp->arp_sha[3], arpResp->arp_sha[4], arpResp->arp_sha[5]);
            printf("Sender Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", arpResp->arp_tha[0], arpResp->arp_tha[1],
                   arpResp->arp_tha[2], arpResp->arp_tha[3], arpResp->arp_tha[4], arpResp->arp_tha[5]);
            printf("Sender IP: %02d:%02d:%02d:%02d\n", arpResp->arp_spa[0], arpResp->arp_spa[1],
                   arpResp->arp_spa[2], arpResp->arp_spa[3]);
            printf("Target IP: %02d:%02d:%02d:%02d\n", arpResp->arp_tpa[0], arpResp->arp_tpa[1],
                   arpResp->arp_tpa[2], arpResp->arp_tpa[3]);
    
            return replyBuffer;
    
        }
    
        return (char*)"fail";
    
    }
    
    
    
    
    void printInterfaces(){
        std::cout << "Interfaces:\n";
	std::map<struct ifaddrs*, int>::iterator it;
   	for(it = socketMap.begin(); it != socketMap.end(); it++){

	std::cout << "Interface : " << it->first->ifa_name << " socket: "
	<< it->second << std::endl; 
	struct sockaddr_ll *mymac  = (struct sockaddr_ll*)it->first->ifa_addr;
        printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",mymac->sll_addr[0],mymac->sll_addr[1],mymac->sll_addr[2],mymac->sll_addr[3],mymac->sll_addr[4],mymac->sll_addr[5]); 
	if (!strncmp(&(it->first->ifa_name)[3], "eth1", 4)){
	std::cout << "found: " << it->first->ifa_name << std::endl;
	}
	std::cout << std::endl;
	}
	
	}
    
    int listen(struct ifaddrs interface, int socket){
        
        int packet_socket = socket;
        
        while(1){
            
            char buf[1500];
            struct sockaddr_ll recvaddr;
            socklen_t recvaddrlen=sizeof(struct sockaddr_ll);
            
            int n = recvfrom(packet_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
        }
        
        return 0;
    }
    
    
    void buildTable(char * filename){
        FILE *fp = fopen(filename, "r");
        char buff[1000];
        fread(buff, 1, 100, fp);
        char *token;
        token = strtok(buff, " \n");

        while (token != NULL){
            printf("%s\n", token);
            token = strtok(NULL, " \n");
        }
    }
};

int main(){
    
    Router test;
    test.printInterfaces();
    
    printf("done");
    
    return 0;
}
