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

/**
 * This class represents a raw socket for sending and receiving IPv6 packets.
 * 
 * @author Ronald Pablos
 */
public class RawIPv6Socket extends RawSocket {

    public RawIPv6Socket(int protocol) throws IOException {
        super(true, protocol);
    }

    @Override
    native int _send(int socket,byte[] srcaddress, byte[] dstaddress, int scopeid, byte[] data, int offset, int length,int ttl,int tos);
    
    @Override
    public MessageInfo receive(byte[] data, int offset, int len) throws IOException {
        byte[] srcaddress = new byte[16];
        byte[] dstaddress = new byte[16];
        return receive(data, offset, len, srcaddress, dstaddress);
    }

    @Override
    native int _receive(int socket, byte[] data, int offset, int length, 
            byte[] scraddress, byte[] dstaddress, 
            int[] interfaceId, int[] ttl, int[] tos);
    
    
    /* RECEIVE PACKET INFO */
    @Override
    native int _getReceivePacketDestination(int socket);

    @Override
    native int _setReceivePacketDestination(int socket, boolean include) ;
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
    /* BIND */
    @Override
    native int _bind(int socket,byte[] address, int scopeid) ;
    
}
