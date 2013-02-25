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

  while (MinetGetNextEvent(event)==0) 
  {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow || event.direction!=MinetEvent::IN) {

      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else 
    {
      //  Data from the IP layer below  //
      if (event.handle==mux) {
	Packet p;
	MinetReceive(mux,p);
  unsigned short len;
  unsigned char flags;
  unsigned int n;
  unsigned short w;
  unsigned int ackn;
  bool checksumok;
	unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
	cerr << "estimated header len="<<tcphlen<<"\n";
	p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
	IPHeader iph=p.FindHeader(Headers::IPHeader);
  IPHeader iphOut=iph;
	TCPHeader tcph=p.FindHeader(Headers::TCPHeader);
  tcph.GetFlags(flags);
  TCPHeader tchphOut=tcph;
  checksumok=tcph.IsCorrectChecksum(p);
  Connection c;
  iph.GetDestIP(c.src);
  iph.GetProtocol(c.protocol);
  tcph.GetDestPort(c.srcport);
  iph.GetSourceIP(c.dest);
  iphOut.SetDestIP(c.dest);
  iphOut.SetSourceIP(c.src);
  tcph.GetSourcePort(c.destport);
  ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
  if (cs!=clist.end()) 
  {
    switch((*cs).state.stateOfcnx)
    {
      case ESTABLISHED:
      //Go-Back-N and start of Teardown
      if(IS_FIN(flags)){
      (*cs).state.SetState(CLOSE_WAIT);
      tcph.GetSeqNum(n);
      tcph.GetAckNum(ackn);
      (*cs).state.SetLastAcked(ackn);
      tcph.GetWinSize(w);
      (*cs).state.SetSendRwnd(w);
      p.SetHeader(iphOut);
      tcph.SetSeqNum((*cs).state.last_sent+1,p);
      (*cs).state.SetLastSent((*cs).state.last_sent+1);
      tcph.SetAckNum(n+1,p);
      tcph.SetWinSize((*cs).state.GetRwnd(),p);
      tcph.SetSourcePort(c.srcport, p);
      tcph.SetDestPort(c.destport,p);
      CLR_FIN(flags);
      SET_ACK(flags);
      tcph.SetFlags(flags,p);
      p.SetHeader(tcph);
    //start timeout
      MinetSend(mux,p);
      }
      else if(IS_ACK(flags))
      {

      }
    break;
    case LISTEN:
    //passive open
    //send synack if pkt=syn
    if(IS_SYN(flags))
    {
    //modify cs for our new connection
      (*cs).state.SetState(SYN_RCVD);
      (*cs).connection.dest = c.dest;
      (*cs).connection.destport = c.destport;
      tcph.GetSeqNum(n);
      tcph.GetWinSize(w);
      (*cs).state.SetLastRcvd(n);
      (*cs).state.SetSendRwnd(w);
      p.SetHeader(iphOut);
      tcph.SetSeqNum((*cs).state.last_acked+1,p);
      (*cs).state.SetLastSent((*cs).state.last_acked+1);
      tcph.SetAckNum(n+1,p);
      tcph.SetWinSize((*cs).state.GetRwnd(),p);
      tcph.SetSourcePort(c.srcport, p);
      tcph.SetDestPort(c.destport,p);
      SET_ACK(flags);
      tcph.SetFlags(flags,p);
      p.SetHeader(tcph);
    //start timeout
      MinetSend(mux,p);
    }
    break;
    case SYN_RCVD:
    if(IS_ACK(flags))
    { tcph.GetAckNum(ackn);
      tcph.GetSeqNum(n);
      (*cs).state.SetState(ESTABLISHED);
      tcph.GetWinSize(w);
      (*cs).state.SetLastRcvd(n);
      (*cs).state.SetSendRwnd(w);
      (*cs).state.SetLastAcked(ackn);
    //start timeout
    }
    break;
    //Wait for ack or timeout
    //Not sending anything
    case SYN_SENT:
    //Wait for synack or timeout
    //send ACK
    if(IS_ACK(flags)&&IS_SYN(flags))
    {
     (*cs).state.SetState(ESTABLISHED);
      tcph.GetSeqNum(n);
      tcph.GetAckNum(ackn);
      (*cs).state.SetLastAcked(ackn);
      tcph.GetWinSize(w);
      (*cs).state.SetSendRwnd(w);
      p.SetHeader(iphOut);
      tcph.SetSeqNum((*cs).state.last_acked+1,p);
      (*cs).state.SetLastSent((*cs).state.last_acked+1);
      tcph.SetAckNum(n+1,p);
      tcph.SetWinSize((*cs).state.GetRwnd(),p);
      tcph.SetSourcePort(c.srcport, p);
      tcph.SetDestPort(c.destport,p);
      CLR_SYN(flags);
      tcph.SetFlags(flags,p);
      p.SetHeader(tcph);
    //start timeout
      MinetSend(mux,p);
    }
    break;
    case FIN_WAIT1:
    if(IS_FIN(flags)&&IS_ACK(flags))
    {
      (*cs).state.SetState(TIME_WAIT);
      tcph.GetSeqNum(n);
      tcph.GetAckNum(ackn);
      (*cs).state.SetLastAcked(ackn);
      tcph.GetWinSize(w);
      (*cs).state.SetSendRwnd(w);
      p.SetHeader(iphOut);
      tcph.SetSeqNum((*cs).state.last_acked+1,p);
      (*cs).state.SetLastSent((*cs).state.last_acked+1);
      tcph.SetAckNum(n+1,p);
      tcph.SetWinSize((*cs).state.GetRwnd(),p);
      tcph.SetSourcePort(c.srcport, p);
      tcph.SetDestPort(c.destport,p);
      CLR_FIN(flags);
      tcph.SetFlags(flags,p);
      p.SetHeader(tcph);
    //start timeout
      MinetSend(mux,p);
    }
    else if(IS_ACK(flags))
    {
      tcph.GetAckNum(ackn);
      tcph.GetSeqNum(n);
      (*cs).state.SetState(FIN_WAIT2);
      tcph.GetWinSize(w);
      (*cs).state.SetLastRcvd(n);
      (*cs).state.SetSendRwnd(w);
      (*cs).state.SetLastAcked(ackn);

    }
    break;
    //rcv: fin, ack, finack
    //send ack, nothing, ack
    //goto CLOSING, WAIT_2, TIME_WAIT
    case FIN_WAIT2:
    //RCV: FIN
    //SEND: ACK
    //GOTO: TIME WAIT
    if(IS_FIN(flags)){
      (*cs).state.SetState(TIME_WAIT);
      tcph.GetSeqNum(n);
      tcph.GetWinSize(w);
      (*cs).state.SetSendRwnd(w);
      p.SetHeader(iphOut);
      tcph.SetSeqNum((*cs).state.last_sent+1,p);
      (*cs).state.SetLastSent((*cs).state.last_sent+1);
      tcph.SetAckNum(n+1,p);
      tcph.SetWinSize((*cs).state.GetRwnd(),p);
      tcph.SetSourcePort(c.srcport, p);
      tcph.SetDestPort(c.destport,p);
      SET_ACK(flags);
      CLR_FIN(flags);
      tcph.SetFlags(flags,p);
      p.SetHeader(tcph);
    //start timeout
      MinetSend(mux,p);
    }
    break;
    //case TIME_WAIT:
    //WAIT 2 RTT, ERASE
    case LAST_ACK:
    if(IS_ACK(flags)){
      tcph.GetAckNum(ackn);
      tcph.GetSeqNum(n);
      (*cs).state.SetState(CLOSED);
      tcph.GetWinSize(w);
      (*cs).state.SetLastRcvd(n);
      (*cs).state.SetSendRwnd(w);
      (*cs).state.SetLastAcked(ackn);
    }
    break;
    //RCV: ACK
    //SEND: NOTHING
    //ERASE.
    default:
    //Freak out. Shouldn't occur.
    cerr<<"Mysterious state error";

    }


  }
  else
  {
    cerr<<"UNKNOWN PORT";
  }
	cerr << "TCP Packet: IP Header is "<<iph<<" and ";
	cerr << "TCP Header is "<<tcph << " and ";
	cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
	
      }
      //  Data from the Sockets layer above  //
      if (event.handle==sock) 
      {
	SockRequestResponse s;
	MinetReceive(sock,s);
	cerr << "Received Socket Request:" << s << endl;
	
	switch(s.type)
  {
	case CONNECT:
	//active open
	case ACCEPT:
	//passive open - will not have dest addr
	case STATUS:
	//status update (in response to a write to socket)
	case WRITE:
	//send data (for conection after successful ACCEPT or CONNECT)
	case FORWARD:
	//ignore, send zero error STATUS
	case CLOSE:
	//close connection
	default:	
	}
	
	
      }
    }
  }
  return 0;
}
