# RawSocket
Raw sockets for Java.
## Some features ##
- Raw socket for IPv4 and IPv6
- Extended information for sending
  - TTL
  - ToS
  - Source address
  - Destination address
- Extended information when receiving packets:
  - Source address information
  - Destination address information
  - ToS
  - TTL
  - incoming interface index

### Fragment example for receiving ###

        ...
        RawIPv4Socket s = new RawIPv4Socket(RawSocket.getProtocolByName("icmp"));
        
        s.setReceivePacketDestination(true);
        s.setReceiveTTL(true);
        s.setReceiveTOS(true);
        s.setReceiveTimeout(20000);
        ...
        RawSocket.MessageInfo msg = s.receive(data, 0, data.length);
        System.out.println(NetworkInterface.getByIndex(msg.incomingInterfaceIndex).getName());
        System.out.println("Dst: "+msg.dstAddress);
        System.out.println("Src: "+msg.scrAddress);
        System.out.println("TTL: "+msg.ttl_hoplimit);
        System.out.println("TOS: "+msg.tos_tc);
        ...
        
### Other useful features ###
There is an implementation of the `select` unix function for handling multiple sockets from the same thread.
 
    ...
    RawSocket[] rsa = new RawSocket[] {s};
    boolean[] rma = new boolean[] {true};
    boolean [] ema = new boolean[] { true};
    
    RawSocket.select(rsa,rma,null, ema,10000);
    
    RawSocket.MessageInfo msg = s.receive(data, 0, data.length);
    ...
