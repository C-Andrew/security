#define debug true

#include <iostream>
#include <string>
#include <sstream>   
#include <pcap.h>
#include <arpa/inet.h>

uint32_t NETMASK_LOW = (10<<24) + (0<<16) + (0<<8) + (0);
uint32_t NETMASK_HIGH = (10<<24) + (255<<16) + (255<<8) + (255);
        
using namespace std;

class Packet_Info{
    public:
        uint32_t src_ip;
        uint32_t dst_ip;
        string src_str;
        string dst_str;
        struct pcap_pkthdr *header;
        Packet_Info(struct pcap_pkthdr *header, const u_char *data);
        bool withinRange();
} ;

Packet_Info::Packet_Info(struct pcap_pkthdr *header, const u_char *data){
    header = header;
    stringstream ss;

    src_ip = (data[26]<<24) + (data[27]<<16) + (data[28]<<8)+ (data[29]);
    dst_ip = (data[30]<<24) + (data[31]<<16) + (data[32]<<8)+ (data[33]);
    // src_ip = (10<<24) + (255<<16) + (255<<8)+ (255);
    // dst_ip = (10<<24) + (155<<16) + (225<<8)+ (256);

    ss << int(data[26]) << "." << int(data[27]) << "." << int(data[28]) <<  "." << int(data[29]);
    src_str = ss.str();

    ss.str("");
    ss << int(data[30]) << "." << int(data[31]) << "." << int(data[32]) <<  "." << int(data[33]);
    dst_str = ss.str();
}

bool Packet_Info::withinRange(){
    bool retval = false;
    if( (src_ip & NETMASK_LOW) == (dst_ip & NETMASK_LOW)){
        retval = true;
    }
    return retval;
}

void print(string s){
    cout << s << endl;
}

void getIpFromData(const u_char *data){  
    for(int i = 0; i < 4; i++){
        printf("%d ", data[30 + i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    
    // Clean up when done
    string pcap_filename = "samples/q2-spoofed.pcap";
    if(argc >= 2){
        pcap_filename = argv[1];
    }

    if(debug){
        print(pcap_filename);        
    }
    // Create pcap structs
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t * pcap = pcap_open_offline(pcap_filename.c_str(), errbuff);
    // Header: info about data
    struct pcap_pkthdr *header;
    // Packet data
    const u_char *data;

    // Part 1: output
    u_int packetCount = 0;
    u_int totalSize = 0;


    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        packetCount++;
        totalSize = totalSize + header->caplen;
        Packet_Info info(header, data);
        if(!info.withinRange()){
            printf("[Spoofed IP address]: src:%s, dst:%s", info.src_str.c_str(), info.dst_str.c_str());
            printf("\n");
        }

        // Show the packet number
        // printf("Packet # %i\n", ++packetCount);
        // Show the size in bytes of the packet
        // printf("Packet size: %d bytes\n", header->len);
 
        // // Show a warning if the length captured is different
        // if (header->len != header->caplen){
        //     // printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
        // }
 
        // // Show Epoch Time
        // // printf("Epoch Time: %ld : %ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);
 
        // // loop through the packet and print it as hexidecimal representations of octets
        // // We also have a function that does this similarly below: PrintData()
        // for (u_int i=0; (i < header->caplen ) ; i++)
        // {
        //     // Start printing on the next after every 16 octets
        //     if ( (i % 16) == 0) printf("\n");
        //     // Print each octet as hex (x), make sure there is always two characters (.2).
        //     printf("%d ", data[i]);
        // }
        // // printf("\n\n");
    }
    printf("Analyzed %d packets, %d bytes", packetCount, totalSize);


    return 0;
}

