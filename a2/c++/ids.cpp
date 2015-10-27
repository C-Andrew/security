#include <iostream>
#include <string>
#include <pcap.h>

using namespace std;
void print(string s){
	cout << s << endl;
}
int main(int argc, char* argv[]) {
	
	string pcap_filename = "q1-anomaly.pcap";
	if(argc >= 2){
		pcap_filename = argv[1];
	}
	print(pcap_filename);
	
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_t * pcap = pcap_open_offline(pcap_filename.c_str(), errbuff);
    
    struct pcap_pkthdr *header;
    const u_char *data;

    u_int packetCount = 0;
    u_int totalSize = 0;
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        // Show the packet number
        packetCount++;
        // printf("Packet # %i\n", ++packetCount);
 		// // Show the size in bytes of the packet
 		totalSize = totalSize + header->caplen;
        // printf("Packet size: %d bytes\n", header->len);
 
        // // Show a warning if the length captured is different
        // if (header->len != header->caplen){
        //     printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
        // }
 
        // // Show Epoch Time
        // printf("Epoch Time: %ld : %ld seconds\n", header->ts.tv_sec, header->ts.tv_usec);
 
        // // loop through the packet and print it as hexidecimal representations of octets
        // // We also have a function that does this similarly below: PrintData()
        // for (u_int i=0; (i < header->caplen ) ; i++)
        // {
        //     // Start printing on the next after every 16 octets
        //     if ( (i % 16) == 0) printf("\n");
        //     // Print each octet as hex (x), make sure there is always two characters (.2).
        //     printf("%.2x ", data[i]);
        // }
        // printf("\n\n");
    }
    printf("Analyzed %d packets, %d bytes", packetCount, totalSize);


	return 0;
}

