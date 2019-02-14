#include <iostream>
#include <unistd.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <set>
#include <vector>
#include <sstream>
#include <fstream>
#include<signal.h>
#include <netdb.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 65535

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

struct UDP_hdr {
    u_short	uh_sport;		/* source port */
    u_short	uh_dport;		/* destination port */
    u_short	uh_ulen;		/* datagram length */
    u_short	uh_sum;			/* datagram checksum */
};

typedef std::tuple<std::string, std::string, uint16_t, uint16_t, std::string>   flow;
typedef std::set<flow> flow_set;
typedef std::map<std::string, flow_set> flow_ip_map;
typedef std::map<std::string, int> packet_ip_map;
typedef std::map<std::string, int> bytes_ip_map;
typedef std::tuple<uint64_t, uint64_t, flow_set, std::string, packet_ip_map, bytes_ip_map, flow_ip_map> report_value;
typedef std::vector<report_value> reports;

struct callback_pointers{
    reports* reports_pointer;
    flow_ip_map* flow_ip_map_pointer;
    packet_ip_map* packet_ip_map_pointer;
    bytes_ip_map* bytes_ip_map_pointer;
};

using namespace std;

void analyzer_callback(u_char *, const struct pcap_pkthdr *, const u_char *);
void analyzer_callback_interface(u_char *, const struct pcap_pkthdr *, const u_char *);
int analyze_savefile(char*, char*, char*, char*);
int analyze_interface(char*, char*, char*, char*);

void showhelpinfo(char *s);

int client(char*, char*);
string analyze_traffic(report_value, report_value, int);

bool iflag = false;
bool rflag = false;

bool savefile_flag = false;
bool savefile_start = false;

bool terminate_flag = false;

double curr_time = 0;
double next_time = 0;

int global_uid = 0;
int UID = 0;
int report_num = 0;
int sockfd, portno;
char* lFile = NULL;

ofstream file;
pcap_t *handle;


void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int main (int argc,char *argv[])
{
    
    char* rFile = NULL;
    char* interface = NULL;
    char* lFile = NULL;
    char* desman_ip = NULL;
    
    char tmp;
    /*if the program is ran witout options ,it will show the usgage and exit*/
    if(argc == 1)
    {
        showhelpinfo(argv[0]);
        exit(1);
    }
    
    while((tmp=getopt(argc,argv,"r:i:w:c:"))!=-1)
    {
        switch(tmp)
        {
            case 'r':
                rFile = optarg;
                cout<<rFile;
                break;
                
            case 'i':
                interface = optarg;
                cout<<interface;
                break;
                
            case 'w':
                lFile = optarg;
                cout<<lFile;
                break;
                
            case 'c':
                desman_ip = optarg;
                break;
                
            default:
                showhelpinfo(argv[0]);
                break;
        }
    }
    
    if((rFile != NULL && interface != NULL) || (rFile == NULL && interface == NULL) || desman_ip == NULL || lFile == NULL){
        showhelpinfo(argv[0]);
        return -1;
    }
    else if (rFile != NULL){
        if (analyze_savefile(rFile, interface, lFile, desman_ip) == -1) {
            fprintf(stderr,"\nError analyzing\n");
        }
    }
    else if (interface != NULL){
        if (analyze_interface(rFile, interface, lFile, desman_ip) == -1) {
            fprintf(stderr,"\nError analyzing\n");
        }
    }
    return 0;
}

/*funcion that show the help information*/
void showhelpinfo(char *s)
{
    cout<<"Usage:   "<<s<<" [-option] [argument]"<<endl;
    cout<<"option:  "<<"-r  Read the specified pcap file"<<endl;
    cout<<"         "<<"-i  Listen on the specified interface"<<endl;
    cout<<"         "<<"-w  Logfile with the summary report"<<endl;
    cout<<"         "<<"-c  Connect to the specified IP address for the desman"<<endl;
}

void terminate_process(int signum)
{
    pcap_breakloop(handle);
}

int client(char* desman_ip, char* lFile)
{
    ofstream file;
    file.open(lFile, ios::out | ios::app);
    
    int n;
    int uid;
    struct sockaddr_in serv_addr;
    char buffer[256];
    char *pch = NULL;
    bool start = false;
    
    portno = 11353;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");
    
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    inet_aton(desman_ip, &serv_addr.sin_addr);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    
    file << "Connecting to desman at ";
    file << desman_ip;
    file << "...\n";
    
    while(!start){
        bzero(buffer,256);
        n = (int)read(sockfd,buffer,255);
        if (n < 0)
            error("ERROR reading from socket");
        pch = strtok(buffer, " ");
        while (pch != NULL)
        {
            std::string y = pch;
            if (y == "start"){
                start = true;
                cout <<"start";
                file << "Received start...\n";;
            }
            else if (y == "UID"){
                pch = strtok (NULL, " ");
                UID = stoi(pch);
                
                file << "Received ";
                file << UID;
                file << "\n";
            }
            pch = strtok (NULL, " ");
        }
    }
    
    return 0;
}

pcap_t* initializeHandle(char* rFile, char* interface, struct bpf_program fp){
    
    /* most code here taken from sniffex.c*/
    
    char *dev = interface;			/* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    //pcap_t *handle;				/* packet capture handle */
    char filter_exp[] = "ip";		/* filter expression [3] */
    bpf_u_int32 mask;               /* subnet mask */
    bpf_u_int32 net = 0;			/* ip */
    
    if (dev == NULL && rFile != NULL) {
        
        if ((handle = pcap_open_offline_with_tstamp_precision(rFile, PCAP_TSTAMP_PRECISION_MICRO, errbuf)) == NULL)
        {
            fprintf(stderr,"\nError opening dump file\n");
            exit(EXIT_FAILURE);
        }
    }
    else if (dev != NULL && rFile == NULL){
        
        /* get network number and mask associated with capture device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                    dev, errbuf);
            net = 0;
            mask = 0;
        }
        
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(EXIT_FAILURE);
        }
    }
    else {
        fprintf(stderr, "Both File and Interface NULL xor not");
        exit(EXIT_FAILURE);
    }
    
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }
    
    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    
    return handle;
}

string analyze_traffic(report_value previous, report_value current, int report_number){
    
    bool packets = false;
    bool bytes = false;
    bool flows = false;
    
    string report = "";
    string temp = "";
    string ip = "";
    
    ofstream file;
    file.open(lFile, ios::out | ios::app);
    
    report = to_string(global_uid)+". ";
    if(get<0>(current) >= get<0>(previous)*1.5 && get<0>(previous) != 0){
        packets = true;
        int max = 0;
        for(packet_ip_map::iterator it = get<4>(current).begin(); it != get<4>(current).end(); it++){
            if(it->second > max){
                max = it->second;
                ip = it->first;
            }
        }
    }
    
    if(get<1>(current) >= get<1>(previous)*1.5 && get<1>(previous) != 0){
        bytes = true;
        int max = 0;
        for(bytes_ip_map::iterator it = get<5>(current).begin(); it != get<5>(current).end(); it++){
            if(it->second > max){
                max = it->second;
                ip = it->first;
            }
        }
    }
    
    if((get<2>(current)).size() >= (get<2>(previous)).size()*1.5 && (get<2>(previous)).size() != 0){
        flows = true;
        int max = 0;
        for(flow_ip_map::iterator it = get<6>(current).begin(); it != get<6>(current).end(); it++){
            if((it->second).size() > max){
                max = (int)(it->second).size();
                ip = it->first;
                cout<<"ip "<<ip<<endl;
            }
        }
    }
    
    if(packets || bytes || flows){
        report += "alert ";
    }
    
    report += "report " + to_string(report_number) + " ";
    temp = report;
    
    if (packets) {
        temp += " packets ";
    }
    if (bytes) {
        temp += " bytes ";
    }
    if (flows) {
        temp += " flows ";
    }
    
    report += to_string(get<0>(current));
    temp += to_string(get<0>(current));
    report += " ";
    temp += " ";
    report += to_string(get<1>(current));
    temp += to_string(get<1>(current));
    report += " ";
    temp += " ";
    report += to_string((get<2>(current)).size());
    temp += to_string((get<2>(current)).size());
    if(packets || bytes || flows){
        report += " " +ip;
        temp += " " +ip;
    }
    report += "\n";
    temp += "\n";
    file << temp;
    std::cout<< temp;
    return report;
}

int analyze_savefile(char* rFile, char* interface, char* lFile, char* desman_ip){
    
    //pcap_t *handle;                 /* packet capture handle */
    struct bpf_program fp;			/* compiled filter program (expression) */
    savefile_flag = true;
    
    file.open(lFile, ios::out | ios::trunc);
    
    callback_pointers cp;
    reports reports;
    flow_ip_map flow_map;
    packet_ip_map packet_map;
    bytes_ip_map bytes_map;
    
    cp.flow_ip_map_pointer = &flow_map;
    cp.packet_ip_map_pointer = &packet_map;
    cp.bytes_ip_map_pointer = &bytes_map;
    cp.reports_pointer = &reports;
    
    u_char* cp_to_char;
    cp_to_char = (u_char*)&cp;
    
    handle = initializeHandle(rFile, interface, fp);
    if (handle == NULL) {
        fprintf(stderr, "Handle returned NULL");
        return -1;
    }
    
    report_value previous;
    report_value current;
    
    string report = to_string(UID)+". ";
    string log_report = "";
    char buffer[256];
    
    get<0>(previous) = 0;
    get<1>(previous) = 0;
    get<3>(previous) = "";
    
    signal(SIGINT, terminate_process);
    
    /* now we can set our callback function */
    pcap_loop(handle, 0, analyzer_callback, cp_to_char);
    
    /* cleanup */
    // pcap_freecode(&fp);
    pcap_close(handle);
    
    //TODO Wait for start signal.
    client(desman_ip, lFile);
    
    int n;
    
    for (int i = 0; i < reports.size(); i++) {
        //sleep(1000);
        current = reports[i];
        log_report = analyze_traffic(previous, current, i+1);
        report += log_report;
        log_report += "\n";
        
        bzero(buffer,256);
        strcpy(buffer, report.c_str());
        report = "";
        
        n = (int)write(sockfd,buffer,strlen(buffer));
        if (n < 0)
            error("ERROR writing to socket");
        
        if (get<0>(current) != 0) {
            get<0>(previous) = get<0>(current);
        }
        if (get<1>(current) != 0) {
            get<1>(previous) = get<1>(current);
        }
        if ((get<2>(current)).size() != 0) {
            get<2>(previous) = get<2>(current);
        }
        get<3>(previous) = get<3>(current);
        
    }
    file.flush();
    close(sockfd);
    return 0;
}

int analyze_interface(char* rFile, char* interface, char* lFile, char* desman_ip){
    
    //pcap_t *handle;                 /* packet capture handle */
    struct bpf_program fp;			/* compiled filter program (expression) */
    
    ofstream file;
    file.open(lFile, ios::out | ios::app);
    
    callback_pointers cp;
    reports reports;
    flow_ip_map flow_map;
    packet_ip_map packet_map;
    bytes_ip_map bytes_map;
    
    cp.flow_ip_map_pointer = &flow_map;
    cp.packet_ip_map_pointer = &packet_map;
    cp.bytes_ip_map_pointer = &bytes_map;
    cp.reports_pointer = &reports;
    
    u_char* cp_to_char;
    cp_to_char = (u_char*)&cp;
    
    handle = initializeHandle(rFile, interface, fp);
    if (handle == NULL) {
        fprintf(stderr, "Handle returned NULL");
        return -1;
    }
    
    report_value empty;
    
    get<0>(empty) = 0;
    get<1>(empty) = 0;
    get<3>(empty) = "";
    
    reports.push_back(empty);
    reports.push_back(empty);
    
    signal(SIGINT, terminate_process);
    
    //TODO Wait for start signal.
    client(desman_ip, lFile);
    global_uid = UID;
    
    /* now we can set our callback function */
    pcap_loop(handle, 0, analyzer_callback_interface, cp_to_char);
    
    /* cleanup */
    // pcap_freecode(&fp);
    pcap_close(handle);
    
    file.flush();
    close(sockfd);
    return 0;
}

void analyzer_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    
    callback_pointers* cp = (callback_pointers*)args;
    reports* reports = cp->reports_pointer;
    
    flow flow_value;
    report_value report_val;
    flow_set flow_set_value;
    string ip_string;
    
    string protocol = "";
    uint16_t src_prt;
    uint16_t dst_prt;
    
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const struct UDP_hdr *udp;              /* The UDP header */
    
    int size_ip;
    int size_tcp;
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    
    /*switch taken and some of above taken from sniffex.c */
    
    /* determine protocol */
    switch(ip->ip_p) {
            
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            /* define/compute tcp header offset */
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }
            src_prt = ntohs(tcp->th_sport);
            dst_prt = ntohs(tcp->th_dport);
            protocol = "tcp";
            break;
            
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            udp = (struct UDP_hdr*)(packet + SIZE_ETHERNET + size_ip);
            
            if (header->len - (size_ip + SIZE_ETHERNET) < sizeof(struct UDP_hdr))
            {
                printf("   * Invalid UDP header length\n");
                return;
            }
            src_prt = ntohs(udp->uh_sport);
            dst_prt = ntohs(udp->uh_dport);
            protocol = "udp";
            break;
            
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }
    
    if (savefile_flag){
        curr_time = static_cast<double>(header->ts.tv_sec);
        cout<<"sec "<<curr_time<<endl;
        curr_time += static_cast<double>(header->ts.tv_usec)/1000000;
        cout<<"micro ";
        cout<<static_cast<double>(header->ts.tv_usec)<<endl;
        if (curr_time >= next_time){
            next_time = curr_time +1;
            //add report
            get<0>(report_val) = 0;
            get<1>(report_val) = 0;
            get<3>(report_val) = "";
            
            reports->push_back(report_val);
            cout<<"new report" << endl;
        }
        cout.precision(13);
        std::cout<<"curr" << fixed<< curr_time << endl;
        std::cout<<"next" << fixed << next_time<< endl;
    }
    
    get<0>(reports->back())++;
    get<1>(reports->back()) += ntohs(ip->ip_len);
    cout<<"len " <<ntohs(ip->ip_len)<< endl;
    
    get<0>(flow_value) = strdup(inet_ntoa(ip->ip_src));
    get<1>(flow_value) = strdup(inet_ntoa(ip->ip_dst));
    get<2>(flow_value) = src_prt;
    get<3>(flow_value) = dst_prt;
    get<4>(flow_value) = protocol;
    
    cout<<strdup(inet_ntoa(ip->ip_src));
    cout<<" ";
    cout<<strdup(inet_ntoa(ip->ip_dst));
    cout<<" ";
    cout<<src_prt;
    cout<<" ";
    cout<<dst_prt;
    cout<<" ";
    cout<<protocol<<endl;
    
    
    (get<2>(reports->back())).insert(flow_value);
    std::cout<<(get<2>(reports->back())).size() << endl;
    
    get<4>(reports->back()).operator[](strdup(inet_ntoa(ip->ip_dst)))++;
    get<5>(reports->back()).operator[](strdup(inet_ntoa(ip->ip_dst)))++;
    get<6>(reports->back()).operator[](strdup(inet_ntoa(ip->ip_dst))).insert(flow_value);
    
    return;
}

void analyzer_callback_interface(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    
    callback_pointers* cp = (callback_pointers*)args;
    reports* reports = cp->reports_pointer;
    
    flow flow_value;
    report_value report_val;
    flow_set flow_set_value;
    string ip_string;
    
    string protocol = "";
    uint16_t src_prt;
    uint16_t dst_prt;
    
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const struct UDP_hdr *udp;              /* The UDP header */
    
    int size_ip;
    int size_tcp;
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    
    /*switch taken and some of above taken from sniffex.c */
    
    /* determine protocol */
    switch(ip->ip_p) {
            
        case IPPROTO_TCP:
            //printf("   Protocol: TCP\n");
            /* define/compute tcp header offset */
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }
            src_prt = ntohs(tcp->th_sport);
            dst_prt = ntohs(tcp->th_dport);
            protocol = "tcp";
            break;
            
        case IPPROTO_UDP:
            //printf("   Protocol: UDP\n");
            udp = (struct UDP_hdr*)(packet + SIZE_ETHERNET + size_ip);
            
            if (header->len - (size_ip + SIZE_ETHERNET) < sizeof(struct UDP_hdr))
            {
                printf("   * Invalid UDP header length\n");
                return;
            }
            src_prt = ntohs(udp->uh_sport);
            dst_prt = ntohs(udp->uh_dport);
            protocol = "udp";
            break;
            
        case IPPROTO_ICMP:
            return;
        case IPPROTO_IP:
            return;
        default:
            return;
    }
    
    curr_time = static_cast<double>(header->ts.tv_sec);
    curr_time += static_cast<double>(header->ts.tv_usec)/1000000;
    if (curr_time >= next_time){
        
        if(next_time != 0){
            
            //send
            char buffer[256];
            string report = to_string(global_uid)+". ";
            string log_report = analyze_traffic(reports->operator[](0), reports->operator[](1), report_num);
            report = log_report;
            log_report += "\n";
            
            file << log_report;
            log_report = "";
            
            file.flush();
            bzero(buffer,256);
            strcpy(buffer, report.c_str());
            report = "";
            
            int n = -1;
            n = (int)write(sockfd,buffer,strlen(buffer));
            if (n < 0)
                error("ERROR writing to socket");
            
        }
        
        report_num++;
        next_time = curr_time +1;
        //add report
        get<0>(report_val) = 0;
        get<1>(report_val) = 0;
        get<3>(report_val) = "";
        
        reports->operator[](0) = reports->operator[](1);
        reports->pop_back();
        reports->push_back(report_val);
        cout<<"new report" << endl;
    }
    
    get<0>(reports->back())++;
    get<1>(reports->back()) += ntohs(ip->ip_len);
    
    get<0>(flow_value) = strdup(inet_ntoa(ip->ip_src));
    get<1>(flow_value) = strdup(inet_ntoa(ip->ip_dst));
    get<2>(flow_value) = src_prt;
    get<3>(flow_value) = dst_prt;
    get<4>(flow_value) = protocol;
    
    
    (get<2>(reports->back())).insert(flow_value);
    
    get<4>(reports->back()).operator[](strdup(inet_ntoa(ip->ip_dst)))++;
    get<5>(reports->back()).operator[](strdup(inet_ntoa(ip->ip_dst)))++;
    get<6>(reports->back()).operator[](strdup(inet_ntoa(ip->ip_dst))).insert(flow_value);
    
    return;
}
