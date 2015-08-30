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

#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include "RawSocket.h"

static int setIntegerSockOpt(int socket, int level, int option, int value) {
  return setsockopt(socket, level, option, (void*)&value, sizeof(value));
}
static int getIntegerSockOpt(int socket, int level, int option) {
  int value;
  socklen_t size   = sizeof(value);
  int result = getsockopt(socket, level, option, (void*)&value, &size);

  return (result < 0)?-1:value;
}
static struct timeval timevalFromMillis(int millis) {
    struct timeval result;
    result.tv_sec = millis/1000;
    result.tv_usec = (millis % 1000) *1000;
    return result;
}

static int timevalToMillis(struct timeval time) {
    return time.tv_sec *1000+time.tv_usec/1000;
}

static struct sockaddr*
fill_sockaddr_in(JNIEnv *env, struct sockaddr_in *sin, jbyteArray address) {
  jbyte *buf;

  memset(sin, 0, sizeof(struct sockaddr_in));
  sin->sin_family = PF_INET;
  buf = (*env)->GetByteArrayElements(env, address, NULL);
  memcpy(&sin->sin_addr, buf, sizeof(sin->sin_addr));
  (*env)->ReleaseByteArrayElements(env, address, buf, JNI_ABORT);
  return (struct sockaddr *)sin;
}
static struct sockaddr*
fill_sockaddr_in6(JNIEnv *env, struct sockaddr_in6 *sin6, jbyteArray address,
                  int scope_id)
{
  jbyte *buf;

  memset(sin6, 0, sizeof(struct sockaddr_in6));
  sin6->sin6_family = PF_INET6;
  sin6->sin6_scope_id = scope_id;
  buf = (*env)->GetByteArrayElements(env, address, NULL);
  memcpy(&sin6->sin6_addr, buf, sizeof(sin6->sin6_addr));
  (*env)->ReleaseByteArrayElements(env, address, buf, JNI_ABORT);
  return (struct sockaddr *)sin6;
}
static void* init_addr(JNIEnv *env, void *addr, jbyteArray address, int len) {
    jbyte *buf;
    
    buf = (*env)->GetByteArrayElements(env, address, NULL);
    memcpy(addr, buf, len);
    (*env)->ReleaseByteArrayElements(env, address, buf, JNI_ABORT);
    return addr;
}
/*
 * Class:     net_RawSocket
 * Method:    _open
 * Signature: (ZI)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket__1open
  (JNIEnv *env, jobject obj, jboolean ipv6, jint protocol) {
    return socket(ipv6?PF_INET6:PF_INET, SOCK_RAW, protocol);
}

/*
 * Class:     net_RawSocket
 * Method:    _close
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket__1close
  (JNIEnv *env, jobject obj, jint socket){
    return close(socket);
}

/*
 * Class:     net_RawSocket
 * Method:    _setBindToDevice
 * Signature: (ILjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket__1setBindToDevice
  (JNIEnv *env, jobject obj, jint socket, jstring interface){
    const char *interface_cstr = (*env)->GetStringUTFChars(env, interface, NULL);
    int len = strlen(interface_cstr);
    int result = setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, (void*)interface_cstr, len);
    (*env)->ReleaseStringUTFChars(env,interface,interface_cstr);
    return result;
}

/*
 * Class:     net_RawSocket
 * Method:    _setReceiveTimeout
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket__1setReceiveTimeout
  (JNIEnv *env, jobject obj, jint socket, jint millis) {
    struct timeval time = timevalFromMillis(millis);
    return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (void*)&time, sizeof(time));
}

/*
 * Class:     net_RawSocket
 * Method:    _getReceiveTimeout
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket__1getReceiveTimeout
  (JNIEnv *env, jobject obj, jint socket) {
    int result;
    struct timeval time;
    socklen_t size = sizeof(time);
    result = getsockopt(socket,SOL_SOCKET, SO_RCVTIMEO, &time, &size);
    return (result < 0)?result:timevalToMillis(time);
}

/*
 * Class:     net_RawSocket
 * Method:    _setSendTimeout
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket__1setSendTimeout
  (JNIEnv *env, jobject obj, jint socket, jint millis){
    struct timeval time = timevalFromMillis(millis);
    return setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (void*)&time, sizeof(time));
}
/*
 * Class:     net_RawSocket
 * Method:    _getSendTimeout
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket__1getSendTimeout
  (JNIEnv *env, jobject obj, jint socket) {
    int result;
    struct timeval time;
    socklen_t size = sizeof(time);
    result = getsockopt(socket,SOL_SOCKET, SO_SNDTIMEO, &time, &size);
    return (result < 0)?result:timevalToMillis(time);
}

/*
 * Class:     net_RawSocket
 * Method:    _getSendBufferSize
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket__1getSendBufferSize
  (JNIEnv *env, jobject obj, jint socket) {
    return getIntegerSockOpt(socket, SOL_SOCKET, SO_SNDBUF);
}
/*
 * Class:     net_RawSocket
 * Method:    _setSendBufferSize
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket__1setSendBufferSize
  (JNIEnv *env, jobject obj, jint socket, jint size) {
    return setIntegerSockOpt(socket, SOL_SOCKET, SO_SNDBUF,size);
}
/*
 * Class:     net_RawSocket
 * Method:    _getReceiveBufferSize
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket__1getReceiveBufferSize
  (JNIEnv *env, jobject obj, jint socket){
    return getIntegerSockOpt(socket, SOL_SOCKET, SO_RCVBUF);
}

/*
 * Class:     net_RawSocket
 * Method:    _setReceiveBufferSize
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket__1setReceiveBufferSize
  (JNIEnv *env, jobject obj, jint socket, jint size){
    return getIntegerSockOpt(socket, SOL_SOCKET, SO_RCVBUF);
}

/*
 * Class:     net_RawSocket
 * Method:    _getErrnoString
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_net_RawSocket__1getErrnoString
  (JNIEnv *env, jclass cls) {
    char *message = strerror(errno);
    return (*env)->NewStringUTF(env, message);
}

/*
 * Class:     net_RawSocket
 * Method:    getProtocolByName
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket_getProtocolByName
  (JNIEnv *env, jclass cls, jstring name) {
    const char *namestr= (*env)->GetStringUTFChars(env, name, NULL);
    struct protoent *proto = getprotobyname(namestr);
    (*env)->ReleaseStringUTFChars(env, name, namestr);
    return (proto == NULL)?-1:proto->p_proto;
}

/*
 * Class:     net_RawSocket
 * Method:    _select
 * Signature: ([I[Z[Z[ZI)I
 */
JNIEXPORT jint JNICALL Java_net_RawSocket__1select
  (JNIEnv *env, jclass cls, jintArray descriptors, 
        jbooleanArray readmask, jbooleanArray writemask, jbooleanArray exceptmask, jint timeout) {
    int result;
    struct timeval t_timeout;
    struct timeval *pt_timeout;
    fd_set rset, wset, eset;
    int i, len;
    int max = -1;
    jboolean *readmaskarray = NULL;
    jboolean *writemaskarray = NULL;
    jboolean *exceptmaskarray = NULL;
    
    if (timeout >= 0) {
        t_timeout = timevalFromMillis(timeout);
        pt_timeout = &t_timeout;
    }
    else
        pt_timeout = NULL;
    FD_ZERO(&rset); FD_ZERO(&wset); FD_ZERO(&eset);
    len = (*env)->GetArrayLength(env,descriptors);
    jint *descriptorsarray = (*env)->GetIntArrayElements(env,descriptors,NULL);
    if (readmask) readmaskarray = (*env)->GetBooleanArrayElements(env,readmask,NULL);
    if (writemask) writemaskarray = (*env)->GetBooleanArrayElements(env,writemask,NULL);
    if (exceptmask) exceptmaskarray = (*env)->GetBooleanArrayElements(env,exceptmask,NULL);
    for (i = 0; i < len; i++) {
        if (descriptorsarray[i] > max)
            max = descriptorsarray[i];
        if (readmaskarray && (readmaskarray[i]))
            FD_SET(descriptorsarray[i],&rset);
        if (writemaskarray && (writemaskarray[i]))
            FD_SET(descriptorsarray[i],&wset);
        if ((exceptmaskarray && exceptmaskarray[i]))
            FD_SET(descriptorsarray[i],&eset);
    }
    
    result = select(max+1,&rset,&wset,&eset,pt_timeout);
    if (result >=0)
        for (i = 0; i < len; i++) {
            if (readmaskarray) readmaskarray[i] = FD_ISSET(descriptorsarray[i],&rset);
            if (writemaskarray) writemaskarray[i] = FD_ISSET(descriptorsarray[i],&wset);
            if (exceptmaskarray) exceptmaskarray[i] = FD_ISSET(descriptorsarray[i],&eset);
        }
    (*env)->ReleaseIntArrayElements(env,descriptors,descriptorsarray,JNI_ABORT);
    if (readmaskarray) (*env)->ReleaseBooleanArrayElements(env,readmask,readmaskarray,JNI_ABORT);
    if (writemaskarray) (*env)->ReleaseBooleanArrayElements(env,writemask,writemaskarray,JNI_ABORT);
    if (exceptmaskarray) (*env)->ReleaseBooleanArrayElements(env,exceptmask,exceptmaskarray,JNI_ABORT);
    return result;
}



/*
 * Class:     net_RawIPv4Socket
 * Method:    _send
 * Signature: (I[B[BI[BII)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1send
  (JNIEnv *env, jobject obj, jint socket, jbyteArray srcaddress, jbyteArray dstaddress, jint dstscope,
        jbyteArray data, jint offset, jint len, jint ttl, jint tos) {
    int result;
    jbyte *buf;

    struct sockaddr_in sin;
    struct sockaddr *saddr;

    struct msghdr mhdr;
    struct iovec iovecs[1];
    char msg_control_buffer[CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(struct in_pktinfo))]; 
    int controllen;
    struct cmsghdr *cmsg;
    struct in_pktinfo *pktinfo;
    int *sent_ttl;
    int *sent_tos;
    

    saddr = fill_sockaddr_in(env, &sin, dstaddress);
  
    buf = (*env)->GetByteArrayElements(env, data, NULL);

    mhdr.msg_name = saddr;
    mhdr.msg_namelen = sizeof(sin);
    iovecs[0].iov_base= &buf[offset];
    iovecs[0].iov_len = len;
    mhdr.msg_iov = &iovecs[0];
    mhdr.msg_iovlen = 1;
    mhdr.msg_controllen = sizeof(msg_control_buffer);
    mhdr.msg_control = msg_control_buffer;
    controllen = 0;
    cmsg = CMSG_FIRSTHDR(&mhdr);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);
    pktinfo->ipi_ifindex = 0;
    pktinfo->ipi_spec_dst.s_addr = 0; //source address not specified 
    if (srcaddress != NULL)
        init_addr(env,&pktinfo->ipi_spec_dst,srcaddress,sizeof(struct in_addr));
    controllen += CMSG_SPACE(sizeof(struct in_pktinfo));  
    cmsg = (struct cmsghdr *)((unsigned char*)cmsg + CMSG_SPACE(sizeof(struct in_pktinfo)));
    if (ttl >=0) {
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_TTL;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        sent_ttl = (int *)CMSG_DATA(cmsg);
        *sent_ttl = ttl;
        controllen += CMSG_SPACE(sizeof(int));
        cmsg = (struct cmsghdr *)((unsigned char*)cmsg + CMSG_SPACE(sizeof(int)));
    }
    if (tos >=0) {
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_TOS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        sent_tos = (int *)CMSG_DATA(cmsg);
        *sent_tos = tos;
        controllen += CMSG_SPACE(sizeof(int));
        cmsg = (struct cmsghdr *)((unsigned char*)cmsg + CMSG_SPACE(sizeof(int)));
    }
    mhdr.msg_controllen = controllen;    
    
    result = sendmsg(socket,&mhdr,0);

    (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);

    return result;
}

/*
 * Class:     net_RawIPv4Socket
 * Method:    _setReceiveTTL
 * Signature: (IZ)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1setReceiveTTL
  (JNIEnv *env, jobject obj, jint socket, jboolean recvTTL) {
    return setIntegerSockOpt(socket,IPPROTO_IP,IP_RECVTTL,recvTTL);
}
/*
 * Class:     net_RawIPv4Socket
 * Method:    _getReceiveTTL
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1getReceiveTTL
  (JNIEnv *env, jobject obj, jint socket) {
    return getIntegerSockOpt(socket,IPPROTO_IP,IP_RECVTTL);
}
/*
 * Class:     net_RawIPv4Socket
 * Method:    _setReceiveTOS
 * Signature: (IZ)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1setReceiveTOS
  (JNIEnv *env, jobject obj, jint socket, jboolean recvTOS) {
    return setIntegerSockOpt(socket,IPPROTO_IP,IP_RECVTOS,recvTOS);
}

/*
 * Class:     net_RawIPv4Socket
 * Method:    _getReceiveTOS
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1getReceiveTOS
  (JNIEnv *env, jobject obj, jint socket) {
    return getIntegerSockOpt(socket,IPPROTO_IP,IP_RECVTOS);
}
/*
 * Class:     net_RawIPv4Socket
 * Method:    _setTOS
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1setTOS
  (JNIEnv *env, jobject obj, jint socket, jint tos) {
    return setIntegerSockOpt(socket, IPPROTO_IP, IP_TOS, tos);
}

/*
 * Class:     net_RawIPv4Socket
 * Method:    _getTOS
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1getTOS
  (JNIEnv *env, jobject obj, jint socket) {
    return getIntegerSockOpt(socket, IPPROTO_IP, IP_TOS);
}

/*
 * Class:     net_RawIPv4Socket
 * Method:    _setTTL
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1setTTL
  (JNIEnv *env, jobject obj, jint socket, jint ttl) {
    return setIntegerSockOpt(socket, IPPROTO_IP, IP_TTL, ttl);
}
/*
 * Class:     net_RawIPv4Socket
 * Method:    _getTOS
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1getTTL
  (JNIEnv *env, jobject obj, jint socket) {
    return getIntegerSockOpt(socket, IPPROTO_IP, IP_TTL);
}

/*
 * Class:     net_RawIPv4Socket
 * Method:    _setIPHeaderInclude
 * Signature: (IZ)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1setIPHeaderInclude
  (JNIEnv *env, jobject obj, jint socket, jboolean recvHeader) {
    return setIntegerSockOpt(socket,IPPROTO_IP,IP_HDRINCL,recvHeader);
}

/*
 * Class:     net_RawIPv4Socket
 * Method:    _getIPHeaderInclude
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1getIPHeaderInclude
  (JNIEnv *env, jobject obj, jint socket) {
    return getIntegerSockOpt(socket,IPPROTO_IP,IP_HDRINCL);
}

/*
 * Class:     net_RawIPv4Socket
 * Method:    _getReceivePacketDestination
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1getReceivePacketDestination
  (JNIEnv *env, jobject obj, jint socket) {
    return getIntegerSockOpt(socket, IPPROTO_IP,IP_PKTINFO);
}

/*
 * Class:     net_RawIPv4Socket
 * Method:    _setReceivePacketDestination
 * Signature: (IZ)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1setReceivePacketDestination
  (JNIEnv *env, jobject obj, jint socket, jboolean recvDst) {
    return setIntegerSockOpt(socket,IPPROTO_IP,IP_PKTINFO,recvDst);
}

/*
 * Class:     net_RawIPv4Socket
 * Method:    _receive
 * Signature: (I[BII[B[B[I[I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1receive
  (JNIEnv *env, jobject obj, jint socket, jbyteArray data, jint offset, jint len, 
        jbyteArray srcaddress, jbyteArray dstaddress, jintArray interfaceId, jintArray ttl, jintArray tos) {
    int result;
    jbyte *buf;
    struct sockaddr_in sin;
    struct sockaddr *saddr;
    void *addr;
    size_t addrlen;
    struct msghdr mhdr;
    struct iovec iovecs[1];
    char msg_control_buffer[CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(char))+CMSG_SPACE(sizeof(struct in_pktinfo))]; 
    struct cmsghdr *cmsg;
    int *ttlptr, *tosptr,*interfaceidptr;
    int received_ttl = -1;
    int received_tos = -1;
    struct in_pktinfo *preceived_pktinfo = NULL;

    
    addrlen = sizeof(sin.sin_addr);
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = PF_INET;
    saddr = (struct sockaddr *)&sin;
    addr = &sin.sin_addr;

    buf = (*env)->GetByteArrayElements(env, data, NULL);

    mhdr.msg_name = saddr;
    mhdr.msg_namelen = sizeof(sin);
    iovecs[0].iov_base= &buf[offset];
    iovecs[0].iov_len = len;
    mhdr.msg_iov = &iovecs[0];
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = msg_control_buffer;
    mhdr.msg_controllen = sizeof(msg_control_buffer);

    result = recvmsg(socket, &mhdr,0);
    if ((result < 0) && (errno == EAGAIN || errno == EWOULDBLOCK))
        result = -2; // value for time out
    (*env)->ReleaseByteArrayElements(env, data, buf, 0);
    if (result <0)
        return result;
      for (cmsg = CMSG_FIRSTHDR(&mhdr); cmsg != NULL;
              cmsg = CMSG_NXTHDR(&mhdr,cmsg)) {
          if (cmsg->cmsg_level == IPPROTO_IP) {
            if (cmsg->cmsg_type == IP_TTL) {
                ttlptr = (int *) CMSG_DATA(cmsg);
                received_ttl = *ttlptr;
            } else if (cmsg->cmsg_type == IP_TOS) {
                received_tos = *((char *) CMSG_DATA(cmsg));
            } else if (cmsg->cmsg_type == IP_PKTINFO) {
                preceived_pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);
            }
          }
      }

    if (srcaddress != NULL) {
      buf = (*env)->GetByteArrayElements(env, srcaddress, NULL);
      memcpy(buf, addr, addrlen);
      (*env)->ReleaseByteArrayElements(env, srcaddress, buf, 0);
    }
    if (ttl != NULL) {
      ttlptr = (*env)->GetIntArrayElements(env, ttl, NULL);
      ttlptr[0] = received_ttl;
      (*env)->ReleaseIntArrayElements(env, ttl, ttlptr, 0);
    }
    if (tos != NULL) {
      tosptr = (*env)->GetIntArrayElements(env, tos, NULL);
      tosptr[0] = received_tos;
      (*env)->ReleaseIntArrayElements(env, tos, tosptr, 0);
    }
    if ((preceived_pktinfo != NULL) && (dstaddress != NULL)) {
        buf = (*env)->GetByteArrayElements(env, dstaddress, NULL);
        memcpy(buf, &preceived_pktinfo->ipi_addr, sizeof(struct in_addr));
        (*env)->ReleaseByteArrayElements(env, dstaddress, buf, 0);
    }
    if ((preceived_pktinfo != NULL) && (interfaceId != NULL)) {
        interfaceidptr = (*env)->GetIntArrayElements(env, interfaceId, NULL);
        interfaceidptr[0] = preceived_pktinfo->ipi_ifindex;
        (*env)->ReleaseIntArrayElements(env, interfaceId, interfaceidptr, 0);
    }

    return result;
}

/*
 * Class:     net_RawIPv4Socket
 * Method:    _bind
 * Signature: (I[BI)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv4Socket__1bind
  (JNIEnv *env, jobject obj, jint socket, jbyteArray address, jint scopeid) {
    struct sockaddr *saddr;
    struct sockaddr_in sin;
    saddr = fill_sockaddr_in(env, &sin, address);

    return bind(socket, saddr, sizeof(sin));
}

/*
 * Class:     net_RawIPv6Socket
 * Method:    _setReceiveTTL
 * Signature: (IZ)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1setReceiveTTL
  (JNIEnv *env, jobject obj, jint socket, jboolean recv) {
    return setIntegerSockOpt(socket,IPPROTO_IPV6,IPV6_RECVHOPLIMIT,recv);
}

/*
 * Class:     net_RawIPv6Socket
 * Method:    _getReceiveTTL
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1getReceiveTTL
  (JNIEnv *env, jobject obj, jint socket) {
    return getIntegerSockOpt(socket, IPPROTO_IPV6,IPV6_RECVHOPLIMIT);
}

/*
 * Class:     net_RawIPv6Socket
 * Method:    _setReceiveTOS
 * Signature: (IZ)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1setReceiveTOS
  (JNIEnv *env, jobject obj, jint socket, jboolean recv) {
    return setIntegerSockOpt(socket,IPPROTO_IPV6,IPV6_RECVTCLASS,recv);
}

/*
 * Class:     net_RawIPv6Socket
 * Method:    _getReceiveTOS
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1getReceiveTOS
  (JNIEnv *env, jobject obj, jint socket){
    return getIntegerSockOpt(socket, IPPROTO_IPV6,IPV6_RECVTCLASS);
}
/*
 * Class:     net_RawIPv6Socket
 * Method:    _setTOS
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1setTOS
  (JNIEnv *env, jobject obj, jint socket, jint tc) {
    return setIntegerSockOpt(socket, IPPROTO_IPV6, IPV6_TCLASS, tc);
}

/*
 * Class:     net_RawIPv6Socket
 * Method:    _getTOS
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1getTOS
  (JNIEnv *env, jobject obj, jint socket) {
    return getIntegerSockOpt(socket,IPPROTO_IPV6,IPV6_TCLASS);
}

/*
 * Class:     net_RawIPv6Socket
 * Method:    _setTTL
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1setTTL
  (JNIEnv *env, jobject obj, jint socket, jint hl) {
    return setIntegerSockOpt(socket, IPPROTO_IPV6, IPV6_HOPLIMIT,hl);
}

/*
 * Class:     net_RawIPv6Socket
 * Method:    _getTTL
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1getTTL
  (JNIEnv *env, jobject obj, jint socket) {
    return getIntegerSockOpt(socket,IPPROTO_IPV6, IPV6_HOPLIMIT);
}

/*
 * Class:     net_RawIPv6Socket
 * Method:    _getReceivePacketDestination
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1getReceivePacketDestination
  (JNIEnv *env, jobject obj, jint socket) {
    return getIntegerSockOpt(socket,IPPROTO_IPV6,IPV6_PKTINFO);
}

/*
 * Class:     net_RawIPv6Socket
 * Method:    _setReceivePacketDestination
 * Signature: (IZ)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1setReceivePacketDestination
  (JNIEnv *env, jobject obj, jint socket, jboolean recvDst) {
    return setIntegerSockOpt(socket,IPPROTO_IPV6,IPV6_PKTINFO,recvDst);
}

/*
 * Class:     net_RawIPv6Socket
 * Method:    _send
 * Signature: (I[B[BI[BII)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1send
  (JNIEnv *env, jobject obj, jint socket, jbyteArray srcaddress, jbyteArray dstaddress, jint dstscopeid,
        jbyteArray data, jint offset, jint len, jint ttl, jint tos) {
    int result;
    jbyte *buf;
    struct sockaddr_in6 sin6;
    struct sockaddr *saddr;
    struct msghdr mhdr;
    struct iovec iovecs[1];
    char msg_control_buffer6[CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(struct in6_pktinfo))]; 
    struct cmsghdr *cmsg;
    int controllen;
    struct in6_pktinfo *pktinfo6;
    int *sent_ttl;
    int *sent_tos;
    
    saddr = fill_sockaddr_in6(env, &sin6, dstaddress, dstscopeid);
 

    buf = (*env)->GetByteArrayElements(env, data, NULL);

    mhdr.msg_name = saddr;
    mhdr.msg_namelen = sizeof(sin6);
    iovecs[0].iov_base= &buf[offset];
    iovecs[0].iov_len = len;
    mhdr.msg_iov = &iovecs[0];
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = msg_control_buffer6;
    mhdr.msg_controllen = sizeof(msg_control_buffer6);
    controllen = 0;
    cmsg = CMSG_FIRSTHDR(&mhdr);
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = 0;
    pktinfo6 = (struct in6_pktinfo*) CMSG_DATA(cmsg);
    pktinfo6->ipi6_ifindex = 0;
    pktinfo6->ipi6_addr = in6addr_any;//source address not specified 
    if (srcaddress != NULL)
        init_addr(env,&pktinfo6->ipi6_addr,srcaddress,sizeof(struct in6_addr));
    controllen += CMSG_SPACE(sizeof(struct in6_pktinfo));  
    cmsg = (struct cmsghdr *)((unsigned char*)cmsg + CMSG_SPACE(sizeof(struct in6_pktinfo)));
    
    if (ttl >=0) {
        
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_HOPLIMIT;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        sent_ttl = (int *)CMSG_DATA(cmsg);
        *sent_ttl = ttl;
        controllen += CMSG_SPACE(sizeof(int));
        cmsg = (struct cmsghdr *)((unsigned char*)cmsg + CMSG_SPACE(sizeof(int)));
    }
    if (tos >=0) {
        cmsg = CMSG_NXTHDR(&mhdr,cmsg);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_TCLASS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        sent_tos = (int *)CMSG_DATA(cmsg);
        *sent_tos = tos;
        controllen += CMSG_SPACE(sizeof(int));
        cmsg = (struct cmsghdr *)((unsigned char*)cmsg + CMSG_SPACE(sizeof(int)));
    }
    mhdr.msg_controllen = controllen;
    
    result = sendmsg(socket,&mhdr,0);

    (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);

    return result;
}

/*
 * Class:     net_RawIPv6Socket
 * Method:    _receive
 * Signature: (I[BII[B[B[I[I[I)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1receive
  (JNIEnv *env, jobject obj, jint socket, jbyteArray data, jint offset, jint len, 
        jbyteArray srcaddress, jbyteArray dstaddress, jintArray interfaceId, jintArray hoplimit, jintArray tclass) {
    int result;
    jbyte *buf;
    struct sockaddr_in6 sin6;
    struct sockaddr *saddr;
    void *addr;
    size_t addrlen;
    struct msghdr mhdr;
    struct iovec iovecs[1];
    char msg_control_buffer[CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(struct in6_pktinfo))]; 
    struct cmsghdr *cmsg;
    int *ttlptr, *tosptr,*interfaceidptr;
    int received_hl = -1;
    int received_tc = -1;
    struct in6_pktinfo *preceived_pktinfo = NULL;

    
    addrlen = sizeof(sin6.sin6_addr);
    memset(&sin6, 0, sizeof(struct sockaddr_in6));
    sin6.sin6_family = PF_INET6;
    saddr = (struct sockaddr *)&sin6;
    addr = &sin6.sin6_addr;

    buf = (*env)->GetByteArrayElements(env, data, NULL);

    mhdr.msg_name = saddr;
    mhdr.msg_namelen = sizeof(sin6);
    iovecs[0].iov_base= &buf[offset];
    iovecs[0].iov_len = len;
    mhdr.msg_iov = &iovecs[0];
    mhdr.msg_iovlen = 1;
    mhdr.msg_control = msg_control_buffer;
    mhdr.msg_controllen = sizeof(msg_control_buffer);

    result = recvmsg(socket, &mhdr,0);
    if ((result < 0) && (errno == EAGAIN || errno == EWOULDBLOCK))
        result = -2; // value for time out
    (*env)->ReleaseByteArrayElements(env, data, buf, 0);
    if (result <0)
        return result;
      for (cmsg = CMSG_FIRSTHDR(&mhdr); cmsg != NULL;
              cmsg = CMSG_NXTHDR(&mhdr,cmsg)) {
          if (cmsg->cmsg_level == IPPROTO_IPV6) {
            if (cmsg->cmsg_type == IPV6_HOPLIMIT) {
                ttlptr = (int *) CMSG_DATA(cmsg);
                received_hl = *ttlptr;
            } else if (cmsg->cmsg_type == IPV6_TCLASS) {
                received_tc = *((int *) CMSG_DATA(cmsg));
            } else if (cmsg->cmsg_type == IPV6_PKTINFO) {
                preceived_pktinfo = (struct in6_pktinfo*) CMSG_DATA(cmsg);
            }
          }
      }

    if (srcaddress != NULL) {
      buf = (*env)->GetByteArrayElements(env, srcaddress, NULL);
      memcpy(buf, addr, addrlen);
      (*env)->ReleaseByteArrayElements(env, srcaddress, buf, 0);
    }
    if (hoplimit != NULL) {
      ttlptr = (*env)->GetIntArrayElements(env, hoplimit, NULL);
      ttlptr[0] = received_hl;
      (*env)->ReleaseIntArrayElements(env, hoplimit, ttlptr, 0);
    }
    if (tclass != NULL) {
      tosptr = (*env)->GetIntArrayElements(env, tclass, NULL);
      tosptr[0] = received_tc;
      (*env)->ReleaseIntArrayElements(env, tclass, tosptr, 0);
    }
    if ((preceived_pktinfo != NULL) && (dstaddress != NULL)) {
        buf = (*env)->GetByteArrayElements(env, dstaddress, NULL);
        memcpy(buf, &preceived_pktinfo->ipi6_addr, sizeof(struct in_addr));
        (*env)->ReleaseByteArrayElements(env, dstaddress, buf, 0);
    }
    if ((preceived_pktinfo != NULL) && (interfaceId != NULL)) {
        interfaceidptr = (*env)->GetIntArrayElements(env, interfaceId, NULL);
        interfaceidptr[0] = preceived_pktinfo->ipi6_ifindex;
        (*env)->ReleaseIntArrayElements(env, interfaceId, interfaceidptr, 0);
    }

    return result;
}
/*
 * Class:     net_RawIPv6Socket
 * Method:    _bind
 * Signature: (I[BI)I
 */
JNIEXPORT jint JNICALL Java_net_RawIPv6Socket__1bind
  (JNIEnv *env, jobject obj, jint socket, jbyteArray address, jint scopeid) {
    struct sockaddr *saddr;
    struct sockaddr_in6 sin6;
    saddr = fill_sockaddr_in6(env, &sin6, address,scopeid);

    return bind(socket, saddr, sizeof(sin6));
}