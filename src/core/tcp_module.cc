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
#include "tcp.h"
#include "constate.h"

using std::cout;
using std::endl;
using std::cerr;
using std::string;

void sendDataPacket(const MinetHandle &mux, struct ConnectionToStateMapping &cs)
{
    unsigned offset;
    unsigned bytes = state.SendBuffer.GetSize();
    size_t packetsize;
    cs.state.SendPacketPayload(offset,packetsize,bytes);
    while (packetsize > 0) {
        char newdata[600];
        cs.state.SendBuffer.GetData(newdata,packetsize,offset);
        Packet p(Buffer(newdata,packetsize));
        IPHeader iph;
        iph.SetDestIP(cs.connection.dest);
        iph.SetSourceIP(cs.connection.src);
        iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH + packetsize);
        iph.SetProtocol(IP_PROTO_TCP);
        
        p.PushFrontHeader(iph);
        
        //Set TCP Header
        TCPHeader tcph;
        tcph.SetSourcePort(cs.connection.srcport, p);
        tcph.SetDestPort(cs.connection.destport, p);
        tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH / 4, p);
        tcph.SetAckNum(cs.state.GetLastRecvd() + 1, p);
        tcph.SetSeqNum(cs.state.last_sent + 1, p);
        tcph.SetWinSize(cs.state.GetRwnd(), p);
        tcph.SetUrgentPtr(0, p);
        
        unsigned char flags = 0;
        SET_ACK(flags);
        tcph.SetFlags(flags, p);
        
        p.PushBackHeader(tcph);
        
        MinetSend(mux,p);
        cs.state.last_sent += packetsize;
        cs.state.SendPacketPayload(offset,packetsize,bytes);
        if(!cs.bTmrActive){
            //set timer if there isn't one already
            cs.timeout = Time()+80;
            //say it's active
            cs.bTmrActive = true;
        }
    }
}

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
  unsigned char iplen;
  unsigned char tcplen;
  unsigned int n;
  unsigned short w;
  unsigned int ackn;
  bool checksumok;
	unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
  iph.GetTotalLength(len);
  iph.GetHeaderLength(iplen);
	cerr << "estimated header len="<<tcphlen<<"\n";
	p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
	IPHeader iph=p.FindHeader(Headers::IPHeader);
  IPHeader iphOut=iph;
	TCPHeader tcph=p.FindHeader(Headers::TCPHeader);
  tcph.GetFlags(flags);
  tcph.GetHeaderLength(tcplen);
  len-=(tcplen*4+iplen*4);
  Buffer &data=p.GetPayload().ExtractFront(len);
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
      tcph.GetSeqNum(n);
      bool validSeq=(*cs).state.SetLastRcvd(n,len);
      if(validSeq){
        if(IS_FIN(flags)){
      (*cs).state.SetState(CLOSE_WAIT);
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
        //sender side
        //(*cs).state.RecvBuffer.AddBack(data);
      SockRequestResponse write(WRITE,
            (*cs).connection,
            data,
            len,
            EOK);
      MinetSend(sock,write);
      }
      else
      {
        //rcvr side
      }
    }
    else{
      p.SetHeader(iphOut);
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
    {//valid segment? move to est
      tcph.GetAckNum(ackn);
      tcph.GetSeqNum(n);
      (*cs).state.SetState(ESTABLISHED);
      tcph.GetWinSize(w);
      (*cs).state.SetLastRcvd(n);
      (*cs).state.SetSendRwnd(w);
      (*cs).state.SetLastAcked(ackn);
      SockRequestResponse write;
      write.type=WRITE;
      write.connection=(*cs).connection;
      write.error=EOK;
      write.bytes=0;
      MinetSend(sock,write);
    //start timeout
    }
    break;
    //Wait for ack or timeout
    //Not sending anything
    case SYN_SENT:
    //Wait for synack or timeout
    //send ACK
    if(IS_ACK(flags)&&IS_SYN(flags))
    { tcph.GetSeqNum(n);
      tcph.GetAckNum(ackn);
      if(ackn==(*cs).state.GetLastSent()){
     (*cs).state.SetState(ESTABLISHED);
      (*cs).state.SetLastAcked(ackn);
      tcph.GetWinSize(w);
      (*cs).state.SetSendRwnd(w);
      p.SetHeader(iphOut);
      tcph.SetSeqNum((*cs).state.last_acked+1,p);
      (*cs).state.SetLastSent((*cs).state.last_acked+1);
      (*cs).state.SetLastRcvd(n);
      tcph.SetAckNum(n+1,p);
      tcph.SetWinSize((*cs).state.GetRwnd(),p);
      tcph.SetSourcePort(c.srcport, p);
      tcph.SetDestPort(c.destport,p);
      CLR_SYN(flags);
      tcph.SetFlags(flags,p);
      p.SetHeader(tcph);
    //start timeout
      MinetSend(mux,p);
    }}
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
	SockRequestResponse repl;
	ConnectionList<TCPState>::iterator cs;
	switch(s.type)
  	{
	case FORWARD:
		repl.type = STATUS;
        	repl.error = ENOT_SUPPORTED;
        	repl.bytes = 0;
        	MinetSend(sock, repl );
		break;
	case CONNECT:
	cs = clist.FindMatching(s.connection);
	if(cs!=clist.end())
	{
	  //if there's a matching connection
	  if((*cs).state.stateOfcnx==CLOSED)
	  {
	  //closed 
	    (*cs).state.SetState(SYN_SENT);
	    //send SYN
	    //
	    //send EOK
          repl.type = STATUS;
          repl.error = EOK;
          repl.connection = s.connection;
          MinetSend( sock, repl );
	  }else if((*cs).state==LISTEN){
  	  //passively open
  	    (*cs).state.connection = c;
	    (*cs).state.SetState(SYN_SENT);
	    //send SYN
	    //
	    //send EOK
	    repl.type = STATUS;
            repl.error = EOK;
            repl.connection = s.connection;
            MinetSend( sock, repl );
	  }
	  else{
	  //already exists - send error to socket
	    cerr << "already open" << std::endl;
	    //send error to socket
	    repl.connection = c;
	    repl.type = STATUS;
	    repl.error = ECONN_FAILED;
	    MinetSend(sock,repl);
	  }
	}else{
	  //doesn't exist
	  TCPState active(1111, SYN_SENT, 0);
	  //send SYN (and start timeout)
          //Create and save mapping
          ConnectionToStateMapping<TCPState> newactive(s.connection, Time(), active, false);
          clist.push_back(newactive);
	  //send EOK
	  repl.type = STATUS;
          repl.error = EOK;
          repl.connection = s.connection;
          MinetSend( sock, repl );
	}
	break;
	case ACCEPT:
	  TCPState listen(0, LISTEN, 0);
	  ConnectionToStateMapping<TCPState> newlisten(s.connection, Time(), listen, false);
          clist.push_back(newlisten);
	  //send OK status
	  repl.type = STATUS;
          repl.error = EOK;
          MinetSend( sock, repl );
	  break;
	case STATUS:
	  cs = clist.FindMatching(c);
	  if((*cs)!=clist.end()){
		//status update (in response to a write to socket)
		//clear front of buffer (# bytes contained in response)
		(*cs).state.RecvBuffer.Erase(0,s.bytes);
	  }else{
		cerr << "unknown connection" << s << std:endl;
	  }
	  break;
	case WRITE:
	  //send data (for conection after successful ACCEPT or CONNECT)
	  cs = clist.FindMatching(c);
	  if(cs!=clist.end())
 	  {
          unsigned numbytes;
	    //if in ESTABLISHED, add to send buffer if there is space
	    // if there are available packets in the window, create them and send them
	    //reply with how many bytes written
          if((*cs).state.stateOfcnx==CLOSED)
          {
              repl.type = STATUS;
              repl.error = ENOMATCH;
              MinetSend(sock,repl);
          }else if ((*cs).state.stateOfcnx==CLOSE_WAIT){
              repl.type = STATUS;
              repl.error = EINVALID_OP;
              MinetSend(sock,repl);
          }else{
              numbytes = MIN_MACRO(s.bytes,(*cs).state.TCP_BUFFER_SIZE-(*cs).state.SendBuffer.GetSize());
              (*cs).state.SendBuffer.AddBack(s.data.ExtractFront(numbytes));
              repl.bytes = numbytes;
              repl.type = STATUS;
              repl.error = EOK;
              repl.connection = s.connection;
              MinetSend(sock,repl);
              //send if it's ESTABLISHED, else leave in queue
              if((*cs).state.stateOfcnx==ESTABLISHED)
                sendDataPacket(mux,(*cs));
          }
	  }else{
	    //no such connection, error
	    repl.type = STATUS;
	    repl.error = ENOMATCH;
	    MinetSend(sock,repl);
	  }
	  break;
	case CLOSE:
	//close connection
	  cs = clist.FindMatching(c);
	  if(cs!=clist.end())
  	  {
	    if((*cs).state.stateOfcnx==ESTABLISHED||(*cs).state.stateOfcnx==SYN_RCVD){
		//if in ESTABLISHED or SYN_RCVD, move to FIN_WAIT_1
		(*cs).state.SetState(FIN_WAIT_1);
		//send FIN
		//
		//send OK
		repl.type = STATUS;
	    	repl.error = EOK;
	    	MinetSend(sock,repl);
	    }else if((*cs).state.stateOfcnx==CLOSE_WAIT){
	    	//if in close_wait, go to LAST_ACK
	    	(*cs).state.SetState(FIN_WAIT_1);
	    	//send FIN
	    	//
	    	//send OK
	    	repl.type = STATUS;
	    	repl.error = EOK;
	    	MinetSend(sock,repl);
	    }else if((*cs).state.stateOfcnx==SYN_SENT){
	      //SYN_SENT... 
	      //
	      //send FIN
	    
	      //go to somewhere?
	        repl.type = STATUS;
	    	repl.error = EOK;
	    	MinetSend(sock,repl);
	    }else{
	    //else... shouldn't be here.
	        repl.type = STATUS;
	        repl.error = ENOMATCH;
	        MinetSend(sock,repl);
	    }
	  }else{
	    //no such connection, error
	    repl.type = STATUS;
	    repl.error = ENOMATCH;
	    MinetSend(sock,repl);
	  }
	  break;
	default:
	//shouldn't be here
	cerr << "unknown socket request unhandled" << s << std::endl;	
	}
	}
      }
  }
  }
  return 0;
}
