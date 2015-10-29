#define debug false

#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include <fstream>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sniff_ethernet.h"

using namespace std;

class IP {
    public:
    uint32_t a, b, c, d;
    IP() : a(0), b(0), c(0), d(0){}
    IP(int a, int b, int c, int d) : a(a), b(b), c(c), d(d){}
    bool validIP();
    string toString();
} ;

bool IP::validIP(){
    bool retval = false;
    if( this->a == 10 ){
        retval = true;
    }
    return retval;
}

string IP::toString(){
    stringstream ss;
    ss << this->a << "." << this->b << "." << this->c <<  "." << this->d;
    return ss.str();
}

IP parseIPV4string(string ipAddress) {
    stringstream s(ipAddress);
    int a,b,c,d;
    char ch;
    s >> a >> ch >> b >> ch >> c >> ch >> d;

    return IP(a,b,c,d);
}

string charArrayToStr(const u_char arr[]){
    int i = 0;
    string s;
    while(arr[i] != '\0'){
        if(arr[i] < 'a'){
            s += ".";
        } else {
            s += arr[i];            
        }
        i++;
    }
    return s;
}

int sizeOfDnsQuery(const u_char arr[]){
    int numOfLabels = 1; // One for intial label
    int i = 0;
    string s;
    while(arr[i] != '\0'){
        if(arr[i] < 'a'){
            s += ".";
            numOfLabels++;
        } else {
            s += arr[i];            
        }
        i++;
    }
    return strlen(s.c_str()) + numOfLabels + 4;
}

map<string, IP> buildSinkholeMap(){
    string line;
    map<string, IP> m;
    ifstream myfile ("sinkholes.txt");
    if (myfile.is_open())
    {
        while ( getline (myfile,line) )
        {   
            IP sinkhole_IP = parseIPV4string(line);
            m.insert( pair<string, IP>(line, sinkhole_IP) );
            // cout << line  << "=>" << sinkhole_IP.toString()<< '\n';
        }
        myfile.close();
    }
    else{
        cout << "Unable to open file";
    }

    return m;
}

int main(int argc, char* argv[]) {
    
    // Clean up when done
    string pcap_filename = "samples/q4-sinkholes.pcap";
    if(argc >= 2){
        pcap_filename = argv[1];
    }

    map<string, IP> sinkholes;
    map<string, IP>::iterator sinkit;
    sinkholes = buildSinkholeMap();

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


    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const struct sniff_udp *udp; /* The UDP header */
    const struct sniff_dns *dns; /* The DNS header */
    const struct sniff_dns_query *dns_query;
    const struct sniff_dns_answer *dns_answer; /* The DNS Answer */
    const u_char *payload; /* Packet payload */

    u_int size_ip;
    u_int size_tcp;
    u_int size_payload;
    u_int size_dns_query;

    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        packetCount++;
        totalSize = totalSize + header->caplen;


        // Parse Data
        // Ethernet Struct
        ethernet = (struct sniff_ethernet*)(data);

        // IP struct
        ip = (struct sniff_ip*)(data + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;

        // Do Generic Packet Checks
        IP ip_src = parseIPV4string(string(inet_ntoa(ip->ip_src)));
        IP ip_dst = parseIPV4string(string(inet_ntoa(ip->ip_dst)));
        // Spoofed
        if(!ip_src.validIP() && !ip_dst.validIP()){
            printf("[Spoofed IP address]: src:%s, dst:%s", ip_src.toString().c_str(), ip_dst.toString().c_str());
            printf("\n");
        }

        // Parse IP-> UDP
        if (ip->ip_p == 17) {
            udp = (struct sniff_udp*)(data + SIZE_ETHERNET + size_ip);

            payload = (u_char *)(data + SIZE_ETHERNET + size_ip + SIZE_UDP);
            size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
            if (size_payload > ntohs(udp->th_ulen)){
                size_payload = ntohs(udp->th_ulen);
            }

            if(ntohs(udp->th_sport) == 53 || ntohs(udp->th_dport) == 53){
                // Deal with DNS Requests
                // Parse DNS for Question & Answer
                dns = (struct sniff_dns*)(data + SIZE_ETHERNET + size_ip + SIZE_UDP);

                // Check if DNS is an Answer
                if(DNS_QR(dns) == 1){
                    dns_query = (struct sniff_dns_query*)(data + SIZE_ETHERNET + size_ip + SIZE_UDP + SIZE_DNS);
                    string url = charArrayToStr(dns_query->th_name);
                    size_dns_query = sizeOfDnsQuery(dns_query->th_name);
                    dns_answer = (struct sniff_dns_answer*)(data + SIZE_ETHERNET + size_ip + SIZE_UDP + SIZE_DNS + size_dns_query);

                    // Check RDATA in sinkhole map
                    struct in_addr ip_addr;
                    ip_addr.s_addr = dns_answer->th_address;
                    IP answer_ip = parseIPV4string(inet_ntoa(ip_addr));
                    // printf("DNS: %s\n", answer_ip.toString().c_str());
                    sinkit = sinkholes.find(answer_ip.toString());
                    if(sinkit != sinkholes.end()){
                        printf("[Sinkhole lookup]: src:%s, host:%s, ip:%s\n",
                         ip_dst.toString().c_str(), url.c_str() ,answer_ip.toString().c_str());
                    }

                }
            }
            // Do UDP
        }
        // Parse IP->TCP
        if(ip->ip_p == 6){
            tcp = (struct sniff_tcp*)(data + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            payload = (u_char *)(data + SIZE_ETHERNET + size_ip + size_tcp);

            // Do TCP Checks
            // Servers
            if(!ip_src.validIP() && ip_dst.validIP() && (tcp->th_flags & TH_SYN) ){
                printf("[Attempted server connection]: rem:%s, srv:%s, port:%d", 
                        ip_src.toString().c_str(), ip_dst.toString().c_str(), ntohs(tcp->th_dport));
                printf("\n");
            }

            if(ip_src.validIP() && !ip_dst.validIP() && (tcp->th_flags & TH_ACK) ){
                printf("[Accepted server connection]: rem:%s, srv:%s, port:%d", 
                        ip_dst.toString().c_str(), ip_src.toString().c_str(), ntohs(tcp->th_sport));
                printf("\n");
            }
        }
    }
    printf("Analyzed %d packets, %d bytes\n", packetCount, totalSize);


    return 0;
}

