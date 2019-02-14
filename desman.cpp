#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <atomic>
#include <thread>
#include <sstream>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void dostuff (int, int, int, char*, const char*);
int server(int, char*);
void error(const char *msg);

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

std::atomic<int> UID(0);



std::atomic<int> combUID(0);
std::atomic<int> totalPackets(0);
std::atomic<int> totalBytes(0);
std::atomic<int> totalFlows(0);
std::atomic<int> totalUID(0);

bool terminate_flag = false;

void terminate_process(int signum)
{
    terminate_flag = true;
}

/*funcion that show the help information*/
void showhelpinfo(char *s)
{
    std::cout<<"Usage:   "<<s<<" [-option] [argument]"<<std::endl;
    std::cout<<"option:  "<<"-i  Listen on the specified interface"<<std::endl;
    std::cout<<"         "<<"-w  Logfile with the summary report"<<std::endl;
    std::cout<<"         "<<"-n  Number of watchdogs to listen"<<std::endl;
}

int main(int argc, char *argv[])
{
    char* rFile = NULL;
    char* interface = NULL;
    char* lFile = NULL;
    char* desman_ip = NULL;
    
    char tmp;
    int n = 0;
    
    /*if the program is ran witout options ,it will show the usgage and exit*/
    if(argc == 1)
    {
        showhelpinfo(argv[0]);
        exit(1);
    }
    
    while((tmp=getopt(argc,argv,"w:n:"))!=-1)
    {
        switch(tmp)
        {
            case 'w':
                lFile = optarg;
                std::cout<<lFile;
                break;
                
            case 'n':
                n = atoi(optarg);
                std::cout << n << std::endl;
                break;
                
            default:
                showhelpinfo(argv[0]);
                break;
        }
    }
    
    if(lFile == NULL || n < 1){
        showhelpinfo(argv[0]);
        return -1;
    }
    else {
        for(int i = 1; i <= n; i++){
            combUID +=i;
        }
        std::cout<<"server";
        server(n, lFile);
    }
    return 0;
}


int server(int x, char* lFile){
    
    std::ofstream file;
    file.open(lFile, std::ios::out | std::ios::trunc);
    
    const char* message = NULL;
    int myUID = 0;
    
    int sockfd, newsockfd, portno, pid;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");
    
    int y = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(int)) < 0)
        error("setsockopt(SO_REUSEADDR) failed");
    
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 11353;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    
    std::cout << "Listening on port 11353...\n";
    file << "Listening on port 11353...\n";
    
    UID = 0;
    while (UID < x) {
        std::cout<<"1" <<std::endl;
        newsockfd = accept(sockfd,(struct sockaddr *) &cli_addr, &clilen);
        std::cout<<"2";
        if (newsockfd < 0)
            error("ERROR on accept");
        
        std::cout <<"Incoming watchdog connection from IP ";
        file << "Incoming watchdog connection from IP ";
        message = inet_ntoa(cli_addr.sin_addr);
        file << message;
        file << "\n";
        
        UID++;
        myUID = UID;
        totalUID += UID;
        
        pid = fork();
        if (pid < 0)
            error("ERROR on fork");
        if (pid == 0)  {
            close(sockfd);
            int myUID = UID;
            std::cout << "dostuff" <<std::endl;
            while(totalUID != combUID){
                
            }
            totalUID = 0;
            dostuff(newsockfd, x, myUID, lFile, message);
            break;
        }
        else {
            std::cout<<"3";
            close(newsockfd);
        }
    } /* end of while */
    
    std::cout<<"Issuing start";
    file << "All watchdogs connected...\n";
    file << "Issuing start monitoring...\n";
    
    while ((pid = waitpid(-1, NULL, 0))) {
        if (errno == ECHILD) {
            break;
        }
    }
    
    //close(sockfd);
    return 0; /* we never get here */
}

void dostuff (int sock, int x, int myUID, char* lFile, const char* message)
{
    std::ofstream file;
    file.open(lFile, std::ios::out | std::ios::app);
    
    file << "Assigned ";
    file << UID;
    file << " to watchdog at IP ";
    file << message;
    file << "\n";
    file.flush();
    int n;
    char buffer[256];
    char* pch = NULL;
    int id = 0;
    
    bzero(buffer,256);
    std::string uid = "UID ";
    uid += std::to_string(myUID);
    uid += " ";
    strcpy(buffer, uid.c_str());
    
    n = (int)write(sock,buffer,strlen(buffer));
    
    while(UID != x){
        
    }
    
    bzero(buffer,256);
    strcpy(buffer, "start");
    n = (int)write(sock,buffer,strlen(buffer));
    signal(SIGINT, terminate_process);
    
    while(terminate_flag == false){
        bzero(buffer,256);
        n = (int)read(sock,buffer,255);
        if (n < 0) error("ERROR reading from socket");
        file << "Received ";
        file << buffer;
        std::cout<< buffer;
        file.flush();
        pch = strtok(buffer, " ");
        id = std::stoi(pch);
        while(pch != NULL){
            std::string y = pch;
            if(y == "report"){
                pch = strtok(NULL, " ");
                totalUID += id;
                pch = strtok(NULL, " ");
                totalPackets += std::stoi(pch);
                pch = strtok(NULL, " ");
                totalBytes += std::stoi(pch);
                pch = strtok(NULL, " ");
                totalFlows += std::stoi(pch);
                
                if(totalUID == combUID){
                    totalUID = 0;
                    file << "Total traffic ";
                    file << totalPackets << " ";
                    file << totalBytes << " ";
                    file << totalFlows << " ";
                    file << "\n";
                    totalPackets = 0;
                    totalBytes = 0;
                    totalFlows = 0;
                }
                
                
            }
          pch = strtok(NULL, " .");
        }
    }

    file.flush();
    
}
