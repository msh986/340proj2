#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;

  MinetInit(MINET_TCP_MODULE);
  ConnectionList<TCPState> clist;
  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;

  while (MinetGetNextEvent(event)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      //  Data from the IP layer below  //
      if (event.handle==mux) {
	Packet p;
	MinetReceive(mux,p);
  unsigned short len;
  bool checksumok;
	unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
	cerr << "estimated header len="<<tcphlen<<"\n";
	p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
	IPHeader iph=p.FindHeader(Headers::IPHeader);
  IPHeader iphOut=iph;
	TCPHeader tcph=p.FindHeader(Headers::TCPHeader);
  TCPHeader tchphOut=tcph;
  checksumok=tcph.IsCorrectChecksum(p);
  Connection c;
  iph.GetDestIP(c.src);
  iph.GetSourceIP(c.dest);
  iphOut.SetDestIP(c.dest);
  iphOut.SetSourceIP(c.src);
  iph.GetProtocol(c.protocol);
  tcph.GetDestPort(c.srcport);
  tcph.GetSourcePort(c.destport);
  tcphOut.SetSourcePort(c.srcport);
  tcphOut.SetDestPort(c.destport);
  ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
  if (cs!=clist.end()) {
    switch((*cs).state)
    {
      case ESTABLISHED:
      //Go-Back-N and start of Teardown
      tcph.GetLength(len);
      len-=tcphlen;
    Buffer &data = p.GetPayload().ExtractFront(len);
    SockRequestResponse write(WRITE,
            (*cs).connection,
            data,
            len,
            EOK);
    break;
    case LISTEN:
    //send synack if pkt=syn 
    case SYN_RCVD:
    //Wait for ack or timeout
    //Not sending anything
    case SYN_SENT:
    //Wait for synack or timeout
    //send ACK
    case FIN_WAIT1:
    //rcv: fin, ack, finack
    //send ack, nothing, ack
    //goto CLOSING, WAIT_2, TIME_WAIT
    case FIN_WAIT2:
    //RCV: FIN
    //SEND: ACK
    //GOTO: TIME WAIT
    case CLOSING:
    //RCV:ACK
    //SEND: Nothing
    //GOTO: TIME WAIT
    case TIME_WAIT:
    //WAIT 2 RTT, ERASE
    case LAST_ACK:
    //RCV: ACK
    //SEND: NOTHING
    //ERASE.
    default:
    //Freak out. Shouldn't occur.
    cerr<<"Mysterious state error";

    }


  }
  else{
    cerr<<"UNKNOWN PORT";
  }
	cerr << "TCP Packet: IP Header is "<<iph<<" and ";
	cerr << "TCP Header is "<<tcph << " and ";
	cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
	
      }
      //  Data from the Sockets layer above  //
      if (event.handle==sock) {
	SockRequestResponse s;
	MinetReceive(sock,s);
	cerr << "Received Socket Request:" << s << endl;
      }
    }
  }
  return 0;
}
