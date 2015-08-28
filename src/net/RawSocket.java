/*
* Copyright 2015 Ronald Pablos.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package net;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * This class represents a raw socket for sending and receiving IP packets.
 * 
 * @author Ronald Pablos
 */
abstract public class RawSocket {

    /**
     * Socket descriptor.
     */
    protected int sd;
    
    /** 
     * Creates a raw socket.
     * 
     * @param ipv6 True to create an IPv6 raw socket. False to create an IPv4 raw socket.
     * @param protocol Protocol number. For example 1 for ICMP.
     * @throws IOException if an error occurs while creating the socket.
     */
    protected RawSocket(boolean ipv6, int protocol) throws IOException {
        sd = _open(ipv6, protocol);
        if (sd < 0)
            throw new IOException(_getErrnoString());
    }
    native private int _open(boolean ipv6, int protocol);
    
    /**
     * Closes the socket. No effect if it is already closed.
     * @throws IOException if an error ocurrs while closing the socket
     */
    public void close() throws IOException {
        if (sd != 0) {
            int result = _close(sd);
            sd = 0;
            if (result < 0)
                throw new IOException(_getErrnoString());
        }
    }
    native private int _close(int socket);
    
    /**
     * Binds the socket to the specified address.
     * @param address The address to bind to.
     * @throws IOException
     */
    public void bind(InetAddress address) throws IOException {
        int result = _bind(sd,address.getAddress(),getScopeId(address));
        if (result < 0)
            throw new IOException(_getErrnoString());
        
    }

    abstract int _bind(int socket,byte[] address,int scopeid);

    /**
     * Binds the socket to the specified network interface.
     * @param interf The interface to bind to. If null, removes the binding.
     * @throws SocketException
     */
    public void setBindToDevice(NetworkInterface interf) throws SocketException {
        int result = _setBindToDevice(sd, (interf != null)?interf.getName():"");
        if (result < 0)
            throw new SocketException(_getErrnoString());
    }
    native private int _setBindToDevice(int socket,String iname);

    /* TIME OUT */

    /**
     * Sets timeout for receiving.
     * 
     * @param millis
     * @throws SocketException
     */

    public void setReceiveTimeout(int millis) throws SocketException {
        int result = _setReceiveTimeout(sd, millis);
        if (result < 0)
            throw new SocketException(_getErrnoString());
    }
    native private int _setReceiveTimeout(int socket, int millis);
    
    /**
     * Gets the timeout for receiving.
     * 
     * @return The timeout.
     * @throws SocketException
     */
    public int getReceiveTimeout() throws SocketException {
        int result = _getReceiveTimeout(sd);
        if (result < 0)
            throw new SocketException(_getErrnoString());
        return result;
    }
    native private int _getReceiveTimeout(int socket);
    
    /**
     * Sets timeout for sending
     * @param millis the timeout in milliseconds.
     * @throws SocketException
     */
    public void setSendTimeout(int millis) throws SocketException {
        int result = _setSendTimeout(sd, millis);
        if (result < 0)
            throw new SocketException(_getErrnoString());
    }
    native private int _setSendTimeout(int socket, int millis);
    /**
     * Gets the timeout for sending.
     * 
     * @return The timeout in milliseconds.
     * @throws SocketException
     */
    public int getSendTimeout() throws SocketException {
        int result = _getSendTimeout(sd);
        if (result < 0)
            throw new SocketException(_getErrnoString());
        return result;
    }
    native private int _getSendTimeout(int socket);
    
    /* SEND BUFFER */
    public int getSendBufferSize() throws SocketException {
        int result = _getSendBufferSize(sd);
        if (result < 0)
            throw new SocketException(_getErrnoString());
        return result;
    }
    native private int _getSendBufferSize(int socket);
    public void setSendBufferSize(int size) throws SocketException {
        int result = _setSendBufferSize(sd, size);
        if (result < 0)
            throw new SocketException(_getErrnoString());
    }
    native private int _setSendBufferSize(int socket, int size);
    
    /* RECEIVE BUFFER */
    public int getReceiveBufferSize() throws SocketException {
        int result = _getReceiveBufferSize(sd);
        if (result < 0)
            throw new SocketException(_getErrnoString());
        return result;
    }
    native private int _getReceiveBufferSize(int socket);
    public void setReceiveBufferSize(int size) throws SocketException {
        int result = _setReceiveBufferSize(sd, size);
        if (result < 0)
            throw new SocketException(_getErrnoString());
    }
    native private int _setReceiveBufferSize(int socket, int size);
    
    /* RECEIVE PACKETINFO */

    /**
     * Returns the value of receive destination packet directive.
     * @return the state of receive packet destination information directive
     * @throws SocketException if an error ocurrs.
     */
    public boolean getReceivePacketDestination() throws SocketException {
        int result = _getReceivePacketDestination(sd);
        if (result < 0)
            throw new SocketException(_getErrnoString());
        return result != 0;
    }
    abstract int _getReceivePacketDestination(int socket);

    /**
     * Sets the destination packet directive.
     * If it is activated, on packet reception, {@link MessageInfo} will include information about destination address and incoming interface.
     * @param include If true, includes the destination information. if false, does not include.
     * @throws SocketException if an error ocurrs.
     */
    public void setReceivePacketDestination(boolean include) throws SocketException {
        int result = _setReceivePacketDestination(sd, include);
        if (result < 0)
            throw new SocketException(_getErrnoString());
    }
    abstract int _setReceivePacketDestination(int socket, boolean include);
    
    /* RECVTTL */
    public void setReceiveTTL(boolean recv) throws SocketException {
        int result = _setReceiveTTL(sd, recv);

        if(result < 0)
          throw new SocketException(_getErrnoString());
    }
    abstract int _setReceiveTTL(int socket, boolean include);
    
    public int getReceiveTTL() throws SocketException {
        int result = _getReceiveTTL(sd);
        if (result < 0)
            throw new SocketException(_getErrnoString());
        return result;
    }
    abstract int _getReceiveTTL(int socket);
    /* RECVTOS */
    public void setReceiveTOS(boolean recv) throws SocketException {
        int result = _setReceiveTOS(sd, recv);

        if(result < 0)
          throw new SocketException(_getErrnoString());
    }
    abstract int _setReceiveTOS(int socket, boolean include);
    
    public int getReceiveTOS() throws SocketException {
        int result = _getReceiveTOS(sd);
        if (result < 0)
            throw new SocketException(_getErrnoString());
        return result;
    }
    abstract int _getReceiveTOS(int socket);
    
    /* TOS */
    public void setTOS(int ttl) throws SocketException {
        int result = _setTOS(sd, ttl);

        if(result < 0)
          throw new SocketException(_getErrnoString());
    }
    abstract int _setTOS(int socket, int ttl);
    
    public int getTOS() throws SocketException {
        int result = _getTOS(sd);
        if (result < 0)
            throw new SocketException(_getErrnoString());
        return result;
    }
    abstract int _getTOS(int socket);
    
    /* TTL */
    public void setTTL(int ttl) throws SocketException {
        int result = _setTTL(sd, ttl);

        if(result < 0)
          throw new SocketException(_getErrnoString());
    }
    abstract int _setTTL(int socket, int ttl);
    
    public int getTTL() throws SocketException {
        int result = _getTTL(sd);
        if (result < 0)
            throw new SocketException(_getErrnoString());
        return result;
    }
    abstract int _getTTL(int socket);
    
    
    /****** SEND *******/
    
    abstract  int _send(int socket, byte[] srcaddress, byte[] dstaddress, int scopeid, byte[] data, int offset, int length, int ttl, int tos);
    
    private int getScopeId (InetAddress address) {
        if (address instanceof Inet6Address)
            return ((Inet6Address)address).getScopeId();
        return 0;
    }
    
    /**
     * <code>{@link #send(java.net.InetAddress, java.net.InetAddress, byte[], int, int, int, int) send}(srcaddress, dstaddress, data, 0 , data.length,-1-1)</code>
     * @param srcaddress Source address of the IP packet
     * @param dstaddress Destination address of the IP packet
     * @param data Payload of IP packet.
     * @return number of octets sent.
     * @throws java.net.SocketTimeoutException If the timeout expires.
     * @throws java.io.IOException If an error ocurrs.
     */
    public int send(InetAddress srcaddress, InetAddress dstaddress, byte[] data) throws IOException {
        return send(srcaddress, dstaddress, data,0,data.length,-1,-1);
    }

    /**
     *  <code>{@link #send(java.net.InetAddress, java.net.InetAddress, byte[], int, int, int, int) send}(srcaddress, dstaddress, data, offset, length,-1-1)</code>
     * @param srcaddress Source address of the IP packet
     * @param dstaddress Destination address of the IP packet
     * @param data Payload of IP packet.
     * @param offset Start offset of data.
     * @param length Length of data.
     * @return number of octets sent.
     * @throws java.net.SocketTimeoutException If the timeout expires.
     * @throws java.io.IOException If an error ocurrs.
     */
    public int send(InetAddress srcaddress, InetAddress dstaddress, byte[] data, int offset, int length) throws IOException {
        return send(srcaddress, dstaddress, data, offset, length, -1, -1);
    }

    /**
     * Sends a packet to the socket
     * 
     * @param srcaddress Source address of the IP packet
     * @param dstaddress Destination address of the IP packet
     * @param data Payload of IP packet.
     * @param offset start offset of data
     * @param length length of data
     * @param ttl Time to live of packet. If negative, default value.
     * @param tos Type of Service of packet. If negative, default value.
     * @return number of octets sent.
     * @throws java.net.SocketTimeoutException If the timeout expires.
     * @throws java.io.IOException If an error ocurrs.
     */
    public int send(InetAddress srcaddress, InetAddress dstaddress, byte[] data, int offset, int length, int ttl, int tos) throws IOException {
        int result = _send(sd,(srcaddress == null)?null:srcaddress.getAddress(),dstaddress.getAddress(),getScopeId(dstaddress),data,offset,length,ttl,tos);
        if (result < 0)
            if ( result == -2) // timeout
                throw new SocketTimeoutException();
            else
                throw new IOException(_getErrnoString());
        return result;
    }
    
    /********** RECEIVE ***********/
    
    /**
     * Receives a packet from socket.
     * The same effect as the call <code>receive(data, 0, data.length)</code>.
     * @param data array to store the received packet
     * @return An {@link MessageInfo} object containing information relative to the received packet.
     * @throws java.net.SocketTimeoutException If the timeout expires.
     * @throws java.io.IOException If an error ocurrs.
    */
    public MessageInfo receive(byte [] data) throws IOException {
        return receive(data, 0, data.length);
    }
    /**
     * Receives a packet from socket.
     * 
     * @param data array to store the received packet
     * @param offset the start offset in the data.
     * @param len length of data array.
     * @return An {@link MessageInfo} object containing information relative to the received packet.
     * @throws java.net.SocketTimeoutException If the timeout expires.
     * @throws java.io.IOException If an error ocurrs.
    */
    abstract public MessageInfo receive(byte [] data,int offset,int len) throws IOException;
    abstract int _receive(int socket, byte[] data, int offset,
                                        int length, 
                                        byte[] scraddress, 
                                        byte[] dstaddress,
                                        int[] interfaceid,
                                        int[] ttl,
                                        int[] tos);
    
    MessageInfo receive(byte[] data, int offset, int len, byte[] srcaddress,byte[] dstaddress) throws IOException {
        int[] ttl = new int[1];
        int[] tos = new int[1];
        int[] intid = new int[1];
        int count = _receive(sd, data, offset, len, srcaddress, dstaddress, intid,ttl, tos);
        if (count < 0)
            if ( count == -2) // timeout
                throw new SocketTimeoutException();
            else
                throw new IOException(_getErrnoString());
        MessageInfo msginfo = new MessageInfo();
        msginfo.octetsRead = count;
        if (srcaddress != null) msginfo.scrAddress = InetAddress.getByAddress(srcaddress);
        if (dstaddress != null) msginfo.dstAddress = InetAddress.getByAddress(dstaddress);
        msginfo.incomingInterfaceIndex = intid[0];
        msginfo.ttl_hoplimit = ttl[0];
        msginfo.tos_tc = tos[0];
        return msginfo;
    }
  

    static protected native String _getErrnoString();
    
    /**
     * Gets the protocol number given its name.
     * @param name protocol name
     * @return protocol number
     */
    public native static int getProtocolByName(String name);

    @Override
    public int hashCode() {
        return sd;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final RawSocket other = (RawSocket) obj;
        return this.sd == other.sd;
    }
    
    
    
    /* load library */
    
    private static void loadLibraryFromClasspath(String name) {
        String libExtension = System.getProperty("os.name").toLowerCase().contains("win") ? "dll" : "so";
        String libName = "lib"+name + "."+libExtension;
        String libdir = System.getProperty("sun.arch.data.model").equals("64")?"lib64":"lib";
        InputStream in = RawSocket.class.getResourceAsStream("/"+libdir+"/"+libName);
        if (in == null) { throw new UnsatisfiedLinkError("Could not locate library in classpath."); }
        try {
            File exportedLib = File.createTempFile(libName,"");
            exportedLib.deleteOnExit();
            BufferedInputStream bIn = null;
            BufferedOutputStream bOut = null;
            
            try {
                bIn = new BufferedInputStream(in);
                bOut = new BufferedOutputStream(new FileOutputStream(exportedLib));
                byte[] buf = new byte[1024];
                int nread;
                while ((nread = bIn.read(buf)) != -1) {
                    bOut.write(buf, 0, nread);
                }

            } finally {
                if (bOut != null) {
                    bOut.flush();
                    bOut.close();
                }
                if (bIn != null) {
                    bIn.close();
                }
            }
            
            System.load(exportedLib.getAbsolutePath());
        } catch (IOException ex) {
            throw new UnsatisfiedLinkError(ex.getMessage());
        }
    }
    static boolean libraryAvailable;

    /**
     * Returns if the native library for raw sockets is available.
     * This way, it is possible to find out programatically if this implemetation of raw sockets can be used.
     * 
     * @return  true if library is available. False otherwise.
     */
    public static boolean isLibraryAvailable() {
        return libraryAvailable;
    }
    static {
        libraryAvailable = true;
        try {
            System.loadLibrary("rawsocket");
        } catch (UnsatisfiedLinkError ex) {
            try {
                loadLibraryFromClasspath("rawsocket");
            } catch (UnsatisfiedLinkError e) {
                libraryAvailable = false;
            }
        }
    }

    /**
     * Instances of this class are returned when receiving packets from socket
     * with the information relative to the receiving packet.
     */
    public static class MessageInfo {

        /**
         * Octets read from socket that conforms the packet
         */
        public int octetsRead;

        /**
         * Source address of the receiving packet.
         */
        public InetAddress scrAddress;
        
        /**
         * Destination address of the receiving packet. Very useful when the socket is not bound to a concrete address.
         * For a valid value, {@link #setReceivePacketDestination(boolean) receiving destination} directive must be activate.
         */
        public InetAddress dstAddress;
        /**
         * Incoming interface of the receiving packet.
         * For a valid value, {@link #setReceivePacketDestination(boolean) receiving destination} directive must be activate.
         * The network interface can be obtain with {@link NetworkInterface#getByIndex(int) NetworkInterface.getByIndex(int).}
         */
        public int incomingInterfaceIndex;

        /**
         * TTL for IPv4 or Hop limit for IPv6 of the receiving packet.
         * For a valid value, {@link RawIPv4Socket#setReceiveTTL(boolean) receiving TTL} or {@link RawIPv6Socket#setReceiveHopLimit(boolean) receiving Hop limit} directive must be activate.
         */
        public int ttl_hoplimit;
        /**
         * TOS for IPv4 or Traffic Class for IPv6 of the receiving packet.
         * For a valid value, {@link RawIPv4Socket#setReceiveTOS(boolean) receiving TOS} or {@link RawIPv6Socket#setReceiveTrafficClass(boolean)  receiving Traffic Class} directive must be activate.
         */
        public int tos_tc;
    }
    
    /**
     * Utility method for <code>select</code> unix function. 
     * <p>
     * Allows to monitor multiple raw sockets, waiting until one o more become ready for IO.
     * <p>
     * If timeout is zero there is no wait, just polling.
     * If timeout is negative integer, waits indefinitely.
     * <p>
     * It it is posible, it is better to use {@link #select(net.RawSocket[], boolean[], boolean[], boolean[], int)  this select} 
     * because this method is just a useful wrapper of it.
     * @param readset Set of sockets to be monitored for reading.
     * @param writeset Set of sockets to be monitored for writing.
     * @param exceptset Set of socket to be monitored for exceptions.
     * @param timeout Interval that should be waited for events in millis.
     * @throws IOException if an error ocurrs during the operation
     */
    public static void select (Set<RawSocket> readset, Set<RawSocket> writeset, Set<RawSocket> exceptset, int timeout) throws IOException {
        int initialCapacity = 0;
        if (readset != null) initialCapacity += readset.size();
        if (writeset != null) initialCapacity += writeset.size();
        if (exceptset != null) initialCapacity += exceptset.size();
        HashSet<RawSocket> unionset = new HashSet<>(initialCapacity);
        if (readset != null) unionset.addAll(readset);
        if (writeset != null) unionset.addAll(writeset);
        if (exceptset != null) unionset.addAll(exceptset);
        
        int[] arrayofsockets = new int[unionset.size()];
        RawSocket[] arrayOfSockets = new RawSocket[unionset.size()];
        int i =0;
        Iterator<RawSocket> iterator = unionset.iterator();
        while (iterator.hasNext()) {
            RawSocket next = iterator.next();
            arrayofsockets[i] = next.sd;
            arrayOfSockets[i++] = next;
        }
        boolean[] readmask = null;
        if (readset != null) readmask = new boolean[arrayofsockets.length];
        boolean[] writemask = null;
        if (writeset != null) writemask = new boolean[arrayofsockets.length];
        boolean[] exceptmask = null;
        if (exceptset != null) exceptmask = new boolean[arrayofsockets.length];
        for (i = 0; i< arrayofsockets.length; i++)
        {
            if ((readset != null) && readset.contains(arrayOfSockets[i]))
                readmask[i] = true;
            if ((writeset != null) && writeset.contains(arrayOfSockets[i]))
                writemask[i] = true;
            if ((exceptset != null) && exceptset.contains(arrayOfSockets[i]))
                exceptmask[i] = true;
        }
        int result = _select(arrayofsockets,readmask,writemask,exceptmask,timeout);
        if (result < 0)
            throw new IOException();
        if ((result == 0) && (timeout > 0))
            throw new SocketTimeoutException();
        if (readset != null) readset.clear();
        if (writeset != null) writeset.clear();
        if (exceptset != null) exceptset.clear();
        for (i = 0; i < arrayofsockets.length; i++) {
            if ((readset != null) && readmask[i])
                readset.add(arrayOfSockets[i]);
            if ((writeset != null) && writemask[i])
                writeset.add(arrayOfSockets[i]);
            if ((exceptset != null) && exceptmask[i])
                exceptset.add(arrayOfSockets[i]);
        }
    }
    
    /**
     * Utility method for <code>select</code> unix function. 
     * <p>
     * Allows to monitor multiple raw sockets, waiting until one o more become ready for IO.
     * <p>
     * An array of raw sockets is passed, as well as three arrays of booleans indicating the interest
     * on reading, writing or exceptions. True for interest. All the arrays must be of the same length.
     * <p>Interests of descriptor in position <i>i</i> are reflected in position <i>i</i> of booleans arrays.
     * 
     * If timeout is zero there is no wait, just polling.
     * If timeout is negative integer, waits indefinitely.
     * 
     * @param rawSockets Array of descriptors.
     * @param readmask Interest on reading for descriptors.
     * @param writemask Interest on writing for descriptors
     * @param exceptmask Interest on exceptions for descriptors
     * @param timeout Interval that should be waited for events in millis.
     * @throws IOException if an error ocurrs during the operation
     */
    public static void select(RawSocket[] rawSockets, boolean[] readmask,boolean[] writemask,boolean[] exceptmask, int timeout) throws IOException {
        int[] arrayofdescriptors = new int[rawSockets.length];
        for (int i = 0; i< arrayofdescriptors.length; i++) {
            arrayofdescriptors[i] = rawSockets[i].sd;
        }
        int result = _select(arrayofdescriptors,readmask,writemask,exceptmask,timeout);
        if (result < 0)
            throw new IOException(_getErrnoString());
        if ((result == 0) && (timeout > 0))
            throw new SocketTimeoutException();
    }
    native private static int _select(int[] arrayofsockets, boolean[] readmask, boolean[] writemask, boolean[] exceptmask, int timeout);
}
