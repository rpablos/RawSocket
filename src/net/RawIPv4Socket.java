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

import java.io.IOException;
import java.net.SocketException;

/**
 * This class represents a raw socket for sending and receiving IPv4 packets.
 * 
 * @author Ronald Pablos
 */

public class RawIPv4Socket extends RawSocket {

    public RawIPv4Socket(int protocol) throws IOException {
        super(false, protocol);
    }

    @Override
    native int _send(int socket,byte[] srcaddress, byte[] dstaddress, int scopeid, byte[] data, int offset, int length, int ttl,int tos);    
    
    /**** RECEIVE TTL ****/
    @Override
    native int _setReceiveTTL(int socket, boolean include);
    @Override
    native int _getReceiveTTL(int socket);
    /* RECVTOS */
    @Override
    native int _setReceiveTOS(int socket, boolean include);
    @Override
    native int _getReceiveTOS(int socket);
    /* TOS */
    @Override
    native int _setTOS(int socket, int ttl);
    @Override
    native int _getTOS(int socket);
    /* TTL */
    @Override
    native int _setTTL(int socket, int ttl);
    @Override
    native int _getTTL(int socket);
    
    /* IP HEADER INCLUDE */
    public void setIPHeaderInclude(boolean include) throws SocketException {
        int result = _setIPHeaderInclude(sd, include);

        if(result < 0)
          throw new SocketException(_getErrnoString());
    }
    native private int _setIPHeaderInclude(int socket, boolean include);
    
    public int getIPHeaderInclude() throws SocketException {
        int result = _getIPHeaderInclude(sd);
        if (result < 0)
            throw new SocketException(_getErrnoString());
        return result;
    }
    native private int _getIPHeaderInclude(int socket);

    @Override
    native int _receive(int socket, byte[] data, int offset,
                                        int length, 
                                        byte[] scraddress, 
                                        byte[] dstaddress,
                                        int[] interfaceid,
                                        int[] ttl, int[] tos);
    @Override
    public MessageInfo receive(byte[] data, int offset, int len) throws IOException {
        byte[] srcaddress = new byte[4];
        byte[] dstaddress = new byte[4];
        return receive(data, offset, len, srcaddress, dstaddress);
    }

    /* RECEIVE PACKET INFO */
    @Override
    native int _getReceivePacketDestination(int socket);

    @Override
    native int _setReceivePacketDestination(int socket,boolean include) ;

    @Override
    native int _bind(int socket,byte[] address, int scopeid) ;
}
