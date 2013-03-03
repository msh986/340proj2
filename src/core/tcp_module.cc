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
#include "tcpstate.h"

using std::cout;
using std::endl;
using std::cerr;
using std::string;
size_t sendDataPacket(const MinetHandle &mux, struct ConnectionToStateMapping<TCPState> &cs)
{     
    unsigned offset=(cs.state.last_sent-cs.state.last_acked>0)?(cs.state.last_sent-cs.state.last_acked):0 ;
    unsigned bytes = cs.state.SendBuffer.GetSize()-offset;
    size_t packetsize;
    Packet p;
    //do {
        unsigned unsentDataInBuffer = cs.state.SendBuffer.GetSize() - offset;
        packetsize = ( unsentDataInBuffer < 536) ? unsentDataInBuffer : 536;
        cerr<<"Packetsize:"<<packetsize<<" unsentDataInBuffer: "<<unsentDataInBuffer<<" offset: "<<offset<<" .\n";
        cs.state.SendPacketPayload(offset,packetsize,bytes);
        char newdata[10000];
        if(cs.state.last_sent==cs.state.last_acked)
        {cs.state.SendBuffer.GetData(newdata,packetsize,offset);
        cerr<<"\nD\n";
        p=Packet(Buffer(newdata,packetsize));
        }
        else
          {
            p= Packet();
            packetsize=0;
          }
        cerr<<"\nE\n";
        IPHeader iph;
        iph.SetDestIP(cs.connection.dest);
        iph.SetSourceIP(cs.connection.src);
        iph.SetHeaderLength(IP_HEADER_BASE_LENGTH/4);
        iph.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH + packetsize);
        iph.SetProtocol(IP_PROTO_TCP);
        
        p.PushFrontHeader(iph);
        cerr<<"\nC\n";
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
        cerr<<"\nD\n";
        cerr<<"\n OUTBOUND PKT HERE\n";
  cerr << "TCP Packet: IP Header is "<<iph<<"\n and ";
  cerr << "TCP Header is "<<tcph << "\n and ";
  cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
  cerr <<"\n Data is: "<<newdata<<"\n";

       //cs.state.SetLastSent(cs.state.last_sent+packetsize);
       //cs.state.SendPacketPayload(offset,packetsize,bytes);
        MinetSend(mux,p);
        if(!cs.bTmrActive){
            //set timer if there isn't one already
           cs.timeout = Time()+80;
            //say it's active
           cs.bTmrActive = true;
        }
    //}while (packetsize > 0);
        return packetsize;
}
void send_data( const MinetHandle & mux, const Connection & c, TCPState & state )
{
    unsigned i = 0;

    std::cerr << "send_data: sending " << state.SendBuffer.GetSize() << " bytes of data over the network"<< std::endl;

    while ( i < state.SendBuffer.GetSize() )
    {
        unsigned unsentDataInBuffer = state.SendBuffer.GetSize() - i;
        unsigned dataToSend = ( unsentDataInBuffer < 536 ) ? unsentDataInBuffer : 536;

        char tempStorage[10000];
        state.SendBuffer.GetData( tempStorage, dataToSend, i );

        Packet ret( Buffer(tempStorage, dataToSend) );

        //Set IP Header
        IPHeader ipHeader;
        ipHeader.SetSourceIP(c.src);
        ipHeader.SetDestIP(c.dest);
        ipHeader.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH + dataToSend);
        ipHeader.SetProtocol(IP_PROTO_TCP);

        ret.PushFrontHeader(ipHeader);

        //Set TCP Header
        TCPHeader tcpHeader;
        tcpHeader.SetSourcePort(c.srcport, ret);
        tcpHeader.SetDestPort(c.destport, ret);
        tcpHeader.SetHeaderLen(TCP_HEADER_BASE_LENGTH / 4, ret);
        tcpHeader.SetAckNum(state.GetLastRecvd() + 1, ret);
        tcpHeader.SetSeqNum(state.last_sent + 1, ret);
        tcpHeader.SetWinSize(state.GetN(), ret);
        tcpHeader.SetUrgentPtr(0, ret);

        unsigned char tempFlags = 0;
        SET_ACK(tempFlags);
        tcpHeader.SetFlags(tempFlags, ret);

        ret.PushBackHeader(tcpHeader);

        MinetSend(mux, ret);

        std::cerr << "send_data: sent " << dataToSend << " bytes of data over the network"<< std::endl;

        state.last_sent += dataToSend;
        i += dataToSend;
    }
}
void sendAck(const MinetHandle &mux, struct ConnectionToStateMapping<TCPState> &cs)
{
    
        Packet p=Packet();
        IPHeader iph;
        iph.SetDestIP(cs.connection.dest);
        iph.SetSourceIP(cs.connection.src);
        iph.SetHeaderLength(IP_HEADER_BASE_LENGTH/4);
        iph.SetTotalLength(40);
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
        cerr<<"\n OUTBOUND PKT HERE\n";
  cerr << "TCP Packet: IP Header is "<<iph<<"\n and ";
  cerr << "TCP Header is "<<tcph << "\n and ";
  cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
  //cerr <<"\n Data is: "<<newdata<<"\n";

      // cs.state.SetLastSent(cs.state.last_sent+packetsize);
      // cs.state.SendPacketPayload(offset,packetsize,bytes);
        MinetSend(mux,p);
        if(!cs.bTmrActive){
            //set timer if there isn't one already
           cs.timeout = Time()+80;
            //say it's active
           cs.bTmrActive = true;
        }
    //}while (packetsize > 0);
}

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;
  Time timeoutVal=-1;
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

  while (MinetGetNextEvent(event,timeoutVal)==0) 
  {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow || event.direction!=MinetEvent::IN) {

      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else 
    {
      //  Data from the IP layer below  //
      if (event.handle==mux) {
	Packet p, pOut;
  pOut=Packet();
	MinetReceive(mux,p);
  unsigned short len;
  unsigned char flags;
  unsigned char iplen;
  unsigned char iplenOut;
  unsigned char tcplen;
  unsigned char tcplenOut;
  unsigned short totlen;
  unsigned short totlenOut;
  unsigned int n;
  unsigned short w;
  unsigned int ackn;
  unsigned char tos;
  size_t numBytesSent;
  bool checksumok;
  bool validSeq;
	unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
  IPHeader iph=p.FindHeader(Headers::IPHeader);
  IPHeader iphOut= IPHeader();
  iph.GetTotalLength(len);
  iph.GetHeaderLength(iplen);
	cerr << "estimated header len="<<tcphlen<<"\n";
	p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
	TCPHeader tcph=p.FindHeader(Headers::TCPHeader);
  tcph.GetFlags(flags);
  tcph.GetHeaderLen(tcplen);
  totlen=len;
  len-=(tcplen*4+iplen*4);
  Buffer &data=p.GetPayload().ExtractFront(len);
  TCPHeader tcphOut=TCPHeader();
  checksumok=tcph.IsCorrectChecksum(p);
  Connection c;
  iph.GetDestIP(c.src);
  iph.GetProtocol(c.protocol);
  iph.GetTOS(tos);
  iphOut.SetTOS(tos);
  tcph.GetDestPort(c.srcport);
  iph.GetSourceIP(c.dest);
  iphOut.SetDestIP(c.dest);
  iphOut.SetSourceIP(c.src);
  iphOut.SetHeaderLength(5);
  iphOut.SetProtocol(c.protocol);
  iphOut.SetTotalLength(40);
  tcph.GetSourcePort(c.destport);
  cerr<<"\n Inbound PKT\n";
  cerr << "TCP Packet: IP Header is "<<iph<<"\n and ";
  cerr << "TCP Header is "<<tcph << "\n and ";
  cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
  ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
  if (cs!=clist.end()) 
  {
    switch((*cs).state.stateOfcnx)
    {
      case ESTABLISHED:
      cerr<<"In mux Established\n";
      tcph.GetSeqNum(n);
      validSeq=(*cs).state.SetLastRecvd(n,len);
      if(validSeq){
        if(IS_FIN(flags)){
      (*cs).state.SetState(CLOSE_WAIT);
      tcph.GetAckNum(ackn);
      (*cs).state.SetLastAcked(ackn);
      tcph.GetWinSize(w);
      (*cs).state.SetSendRwnd(w);
      pOut.PushFrontHeader(iphOut);
      tcphOut.SetSeqNum((*cs).state.GetLastAcked()+1,pOut);
      (*cs).state.SetLastSent((*cs).state.GetLastAcked()+1);
      tcphOut.SetAckNum((*cs).state.GetLastRecvd()+1,pOut);
      tcphOut.SetWinSize((*cs).state.GetRwnd(),p);
      tcphOut.SetSourcePort(c.srcport, pOut);
      tcphOut.SetDestPort(c.destport,pOut);
      CLR_FIN(flags);
      SET_ACK(flags);
      tcphOut.SetFlags(flags,pOut);
      pOut.PushBackHeader(tcphOut);
    //start timeout
      MinetSend(mux,p);
      }
      else if(IS_ACK(flags))
      {cerr<<"\n got valid ack pkt\n";
        //sender side
      tcph.GetAckNum(ackn);
      tcph.GetWinSize(w);
      (*cs).state.SetSendRwnd(w);
      (*cs).state.SetLastAcked(ackn);
      cerr<<"\nSend Buffer:\n"<<(*cs).state.SendBuffer<<"\n";
      (*cs).state.RecvBuffer.AddBack(data);
      cerr<<"Their Data:"<<data<<"\n";

      numBytesSent=sendDataPacket(mux,(*cs));
      (*cs).state.SetLastSent((*cs).state.last_sent+numBytesSent);
      if(len!=0){SockRequestResponse write(WRITE,
            (*cs).connection,
            data,
            len,
            EOK);
          
      MinetSend(sock,write);
    }
     // sendAck(mux,(*cs));
      }
      else
      {
      (*cs).state.RecvBuffer.AddBack(data);
      SockRequestResponse write(WRITE,
            (*cs).connection,
            data,
            len,
            EOK);
      MinetSend(sock,write);
      }
    }
    else{
      //p.SetHeader(iphOut);
    }
    break;
    case LISTEN:
    //passive open
    //send synack if pkt=syn
    cerr<<"\n in mux Listen";
    if(IS_SYN(flags))
    {
    //modify cs for our new connection
      (*cs).state.SetState(SYN_RCVD);
      (*cs).connection.dest = c.dest;
      (*cs).connection.destport = c.destport;
      tcph.GetSeqNum(n);
      tcph.GetWinSize(w);
      (*cs).state.SetLastRecvd(n);
      (*cs).state.SetSendRwnd(w);
      pOut.PushFrontHeader(iphOut);
      tcphOut.SetSeqNum((*cs).state.GetLastAcked()+1,pOut);
      (*cs).state.SetLastSent((*cs).state.GetLastAcked()+1);
      tcphOut.SetAckNum((*cs).state.GetLastRecvd()+1,pOut);
      tcphOut.SetWinSize((*cs).state.GetN(),pOut);
      tcphOut.SetSourcePort(c.srcport, pOut);
      tcphOut.SetDestPort(c.destport,pOut);
      SET_ACK(flags);
      SET_SYN(flags);
      tcphOut.SetHeaderLen(5,pOut);
      tcphOut.SetFlags(flags,pOut);
      tcphOut.SetUrgentPtr(0,pOut);
      pOut.PushBackHeader(tcphOut);
    //start timeout
      MinetSend(mux,pOut);
    }
    break;
    case SYN_RCVD:
    cerr<<"\n in mux SYN_RCVD\n";
    if(IS_ACK(flags))
    {//valid segment? move to est
      tcph.GetAckNum(ackn);
      tcph.GetSeqNum(n);
      (*cs).state.SetState(ESTABLISHED);
      tcph.GetWinSize(w);
      //(*cs).state.SetLastRecvd(n);
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
    cerr<<"in mux SYN_SENT";
    if(IS_ACK(flags)&&IS_SYN(flags))
    { //FIX ME
      tcph.GetSeqNum(n);
      tcph.GetAckNum(ackn);
      if(ackn==(*cs).state.GetLastSent()){
     (*cs).state.SetState(ESTABLISHED);
      (*cs).state.SetLastAcked(ackn);
      tcph.GetWinSize(w);
      (*cs).state.SetSendRwnd(w);
      p.SetHeader(iphOut);
      tcph.SetSeqNum((*cs).state.GetLastAcked()+1,p);
      (*cs).state.SetLastSent((*cs).state.GetLastAcked()+1);
      (*cs).state.SetLastRecvd(n);
      tcph.SetAckNum((*cs).state.GetLastRecvd(),p);
      tcph.SetWinSize((*cs).state.GetN(),p);
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
    cerr<<"in mux FIN_WAIT1";
    if(IS_FIN(flags)&&IS_ACK(flags))
    {//FIX ME
      (*cs).state.SetState(TIME_WAIT);
      tcph.GetSeqNum(n);
      tcph.GetAckNum(ackn);
      (*cs).state.SetLastAcked(ackn);
      tcph.GetWinSize(w);
      (*cs).state.SetSendRwnd(w);
      p.SetHeader(iphOut);
      tcph.SetSeqNum((*cs).state.GetLastAcked()+1,p);
      (*cs).state.SetLastSent((*cs).state.GetLastAcked()+1);
      tcph.SetAckNum((*cs).state.GetLastRecvd()+1,p);
      tcph.SetWinSize((*cs).state.GetRwnd(),p);
      tcph.SetSourcePort(c.srcport, p);
      tcph.SetDestPort(c.destport,p);
      CLR_FIN(flags);
      tcph.SetFlags(flags,p);
      p.SetHeader(tcph);
    //start timeout
      MinetSend(mux,p);
      cerr<<"\n OUTBOUND PKT HERE\n";
      cerr << "TCP Packet: IP Header is "<<iphOut<<"\n and ";
      cerr << "TCP Header is "<<tcphOut << "\n and ";
      cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
    }
    else if(IS_ACK(flags))
    {
      tcph.GetSeqNum(n);
      validSeq=(*cs).state.SetLastRecvd(n,len);
      if(validSeq){
        cerr<<"\nGot a valid sequence number in finwait1\n";
      tcph.GetAckNum(ackn);
      tcph.GetWinSize(w);
      (*cs).state.SetSendRwnd(w);
      (*cs).state.SetLastAcked(ackn);
      if((*cs).state.SendBuffer.GetSize()==0)
      {cerr<<"emptysendbuff";
       (*cs).state.SetState(FIN_WAIT2);
       pOut.PushFrontHeader(iphOut);
      tcphOut.SetSeqNum((*cs).state.GetLastAcked()+1,pOut);
      (*cs).state.SetLastSent((*cs).state.GetLastAcked()+1);
      tcphOut.SetAckNum((*cs).state.GetLastRecvd()+1,pOut);
      tcphOut.SetWinSize((*cs).state.GetN(),pOut);
      tcphOut.SetSourcePort(c.srcport, pOut);
      tcphOut.SetDestPort(c.destport,pOut);
      SET_FIN(flags);
      tcphOut.SetHeaderLen(5,pOut);
      tcphOut.SetFlags(flags,pOut);
      tcphOut.SetUrgentPtr(0,pOut);
      pOut.PushBackHeader(tcphOut);
    //start timeout
      MinetSend(mux,pOut);
      }
      else{
        cerr<<"option2";
        //sendDataPacket(mux,(*cs));
        numBytesSent=sendDataPacket(mux,(*cs));
                (*cs).state.SetLastSent((*cs).state.last_sent+numBytesSent);
      }
      }
    }
    break;
    //rcv: fin, ack, finack
    //send ack, nothing, ack
    //goto CLOSING, WAIT_2, TIME_WAIT
    case FIN_WAIT2:
    //RCV: FIN
    //SEND: ACK
    //GOTO: TIME WAIT
    cerr<<"in mux FIN_W2";
    if(IS_FIN(flags)){
    //   (*cs).state.SetState(TIME_WAIT);
    //   tcph.GetSeqNum(n);
    //   tcph.GetWinSize(w);
    //   (*cs).state.SetSendRwnd(w);
    //   p.SetHeader(iphOut);
    //   tcph.SetSeqNum((*cs).state.last_sent+1,p);
    //   (*cs).state.SetLastSent((*cs).state.last_sent+1);
    //   tcph.SetAckNum(n+1,p);
    //   tcph.SetWinSize((*cs).state.GetRwnd(),p);
    //   tcph.SetSourcePort(c.srcport, p);
    //   tcph.SetDestPort(c.destport,p);
    //   SET_ACK(flags);
    //   CLR_FIN(flags);
    //   tcph.SetFlags(flags,p);
    //   p.SetHeader(tcph);
    // //start timeout
    //   MinetSend(mux,p);
      //
      tcph.GetSeqNum(n);
      validSeq=(*cs).state.SetLastRecvd(n,len);
      if(validSeq){
      cerr<<"\nGot a valid sequence number in finwait2\n";
      tcph.GetAckNum(ackn);
      tcph.GetWinSize(w);
      (*cs).state.SetLastAcked(ackn);
      (*cs).state.SetState(TIME_WAIT);
      pOut.PushFrontHeader(iphOut);
      tcphOut.SetSeqNum((*cs).state.GetLastAcked()+1,pOut);
      (*cs).state.SetLastSent((*cs).state.GetLastAcked()+1);
      tcphOut.SetAckNum((*cs).state.GetLastRecvd()+1,pOut);
      tcphOut.SetWinSize((*cs).state.GetN(),pOut);
      tcphOut.SetSourcePort(c.srcport, pOut);
      tcphOut.SetDestPort(c.destport,pOut);
      SET_ACK(flags);
      tcphOut.SetHeaderLen(5,pOut);
      tcphOut.SetFlags(flags,pOut);
      tcphOut.SetUrgentPtr(0,pOut);
      pOut.PushBackHeader(tcphOut);
    //start timeout
      MinetSend(mux,pOut);
    }
    }
    break;
    //case TIME_WAIT:
    //WAIT 2 RTT, ERASE
    case LAST_ACK:
    cerr<<"In mux last_ack";
    if(IS_ACK(flags)){
      tcph.GetAckNum(ackn);
      tcph.GetSeqNum(n);
      (*cs).state.SetState(CLOSED);
      tcph.GetWinSize(w);
      (*cs).state.SetLastRecvd(n);
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
    break;
    }
  //cerr << "\n TCP Packet: IP Header is "<<iphOut<<"\n and ";
  //cerr << "TCP Header is "<<tcphOut << "\n and ";
 // cerr << "Checksum is " << (tcphOut.IsCorrectChecksum(pOut) ? "VALID" : "INVALID");
//cerr<<"Receiving pkt!";
  }
  else
  {
    cerr<<"UNKNOWN PORT";
  }
	
      }
      //  Data from the Sockets layer above  //
       if (event.handle==sock)
      { TCPState newState(1111, SYN_SENT, 0);
        SockRequestResponse s;
        MinetReceive(sock,s);
        ConnectionToStateMapping<TCPState> newCSM(s.connection, Time(), newState, false);
        cerr << "Received Socket Request:" << s << endl;
        SockRequestResponse repl;
        Connection c=s.connection;
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
            }else if((*cs).state.stateOfcnx==LISTEN){
     //passively open
             (*cs).connection = s.connection;
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
            repl.connection = s.connection;
            repl.type = STATUS;
            repl.error = ECONN_FAILED;
            MinetSend(sock,repl);
          }
        }else{
  //doesn't exist
         // newState =  TCPState(1111, SYN_SENT, 0);
  //send SYN (and start timeout)
            //Create and save mapping
        // newCSM =  ConnectionToStateMapping<TCPState>(s.connection, Time(), newState, false);
          clist.push_back(newCSM);
  //send EOK
          repl.type = STATUS;
          repl.error = EOK;
          repl.connection = s.connection;
          MinetSend( sock, repl );
        }
        break;
        case ACCEPT:
       // newState=  TCPState(0, LISTEN, 0);
       // newCSM= ConnectionToStateMapping<TCPState>(s.connection, Time(), newState, false);
        newCSM.state.SetState(LISTEN);
        newCSM.state.SetLastAcked(0);
        clist.push_back(newCSM);
  //send OK status
        repl.type = STATUS;
        repl.error = EOK;
        MinetSend( sock, repl );
        break;
        case STATUS:
        cs = clist.FindMatching(s.connection);
        if(cs!=clist.end()){
  //status update (in response to a write to socket)
  //clear front of buffer (# bytes contained in response)
          (*cs).state.RecvBuffer.Erase(0,s.bytes);
        }else{
          cerr << "unknown connection" << s << std::endl;
        }
        break;
        case WRITE:
  //send data (for conection after successful ACCEPT or CONNECT)
        cs = clist.FindMatching(s.connection);
        if(cs!=clist.end())
        {
          size_t numbytes;
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
            numbytes = MIN_MACRO(s.data.GetSize(),(*cs).state.TCP_BUFFER_SIZE-(*cs).state.SendBuffer.GetSize());
            (*cs).state.SendBuffer.AddBack(s.data.ExtractFront(numbytes));
            cerr<<"\n the send buffer is\n"<<(*cs).state.SendBuffer<<"\n";
            repl.bytes = numbytes;
            repl.type = STATUS;
            repl.error = EOK;
            repl.connection = s.connection;
            MinetSend(sock,repl);
                //send if it's ESTABLISHED, else leave in queue
             if((*cs).state.stateOfcnx==ESTABLISHED)
              {numbytes=sendDataPacket(mux,(*cs));
               (*cs).state.SetLastSent((*cs).state.last_sent+numbytes);}
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
        cs = clist.FindMatching(s.connection);
        if(cs!=clist.end())
        {
          if((*cs).state.stateOfcnx==ESTABLISHED||(*cs).state.stateOfcnx==SYN_RCVD){
  //if in ESTABLISHED or SYN_RCVD, move to FIN_WAIT_1
            (*cs).state.SetState(FIN_WAIT1);
  //send FIN
  //
  //send OK
            repl.type = STATUS;
            repl.error = EOK;
            MinetSend(sock,repl);
          }else if((*cs).state.stateOfcnx==CLOSE_WAIT){
  //if in close_wait, go to LAST_ACK
            (*cs).state.SetState(FIN_WAIT1);
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
	     cerr<<"Socket event!";
      }
    }
  }
  if(event.eventtype==MinetEvent::Timeout)
  {
    cerr<<"timout here!";
    if(clist.FindEarliest()==clist.end())
    {
      timeoutVal=0;
    }
    else
    {
      timeoutVal=(*(clist.FindEarliest())).timeout;
    }
  }
  return 0;
}

