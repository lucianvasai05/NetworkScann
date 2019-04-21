#include <string>
#include <iostream>
#include <pcap.h>

using namespace std;



typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char *argv[])
{


	string file = "F:\\Tema_Malware\\captura_1.pcap";

	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);
	struct pcap_pkthdr *header;
	const u_char *data;
	u_int packetCount = 0;


	while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
	{
		printf("Packet # %i\n", ++packetCount);
		printf("Packet size: %ld bytes\n", header->len);

		for (u_int i = 0; (i < header->caplen); i++)
		{
			// Start printing on the next after every 16 octets
			if ((i % 16) == 0) printf("\n");

			// Print each octet as hex (x), make sure there is always two characters (.2).
			printf("%.2x ", data[i]);

		}
			// Add two lines between packets
			printf("\n\n");


			if (header->len != header->caplen)
				printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
		
	}
	printf("Epoch Time: %ld:%ld seconds\n ", header->ts.tv_sec, header->ts.tv_usec);
	//for (u_int i = 0; (i < header->caplen); i++)
	//{
	//	// Start printing on the next after every 16 octets
	//	if ((i % 16) == 0) printf("\n");

	//	// Print each octet as hex (x), make sure there is always two characters (.2).
	//	printf("%.2x ", data[i]);
	//}

	//// Add two lines between packets
	printf("\n\n");
	system("pause");
}
