#define SIZE_ETHERNET 14

/* length of UDP header */
#define SIZE_UDP        8               

/* length of UDP header */
#define SIZE_DNS        12

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    tcp_seq th_seq;     /* sequence number */
    tcp_seq th_ack;     /* acknowledgement number */
    u_char th_offx2;    /* data offset, rsvd */
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};

/* UDP header */
struct sniff_udp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    u_short th_ulen;                /* udp length */
    u_short th_sum;                 /* udp checksum */
};

struct sniff_dns {
    u_short query_id;
    u_short codes;
    u_short qdcount;
    u_short ancount; 
    u_short nscount;
    u_short arcount;
} ;
#define DNS_QR(dns)     ((ntohs(dns->codes) & 0x8000) >> 15)

struct sniff_dns_query {
    u_char th_length;
    u_char th_name[];
} ;

struct sniff_dns_answer {
    u_short th_name;
    u_short th_type;
    u_short th_class;
    u_short th_ttl;     // Was skipping 00 00 bytes
    u_short th_ttl2;
    u_short th_rdlength;
    u_int th_address;
} ;
#define dns_answer_ttl(dnsa)     (ntohs((dnsa->th_ttl<<16) | ((dnsa->th_ttl2) & 0xffff)))


