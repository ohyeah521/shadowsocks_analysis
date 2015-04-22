#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# SOCKS5是基于UDP的，所以有这个UDPrelay，用来返回给browser的报文??

# SOCKS5用于browser和proxy协商用
# SOCKS5 UDP Request
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# SOCKS5 UDP Response
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# shadowsocks用于proxy和remote远程沟通用，所以要加密
# shadowsocks UDP Request (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Response (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Request and Response (after encrypted)
# +-------+--------------+
# |   IV  |    PAYLOAD   |
# +-------+--------------+
# | Fixed |   Variable   |
# +-------+--------------+

# HOW TO NAME THINGS
# ------------------
# `dest`    means destination server, which is from DST fields in the SOCKS5
#           request
# `local`   means local server of shadowsocks
# `remote`  means remote server of shadowsocks
# `client`  means UDP clients that connects to other servers
# `server`  means the UDP server that handles user requests

from __future__ import absolute_import, division, print_function, \
    with_statement

import time
import socket
import logging
import struct
import errno
import random

from shadowsocks import encrypt, eventloop, lru_cache, common
from shadowsocks.common import parse_header, pack_addr


BUF_SIZE = 65536


def client_key(a, b, c, d):
    return '%s:%s:%s:%s' % (a, b, c, d)


class UDPRelay(object):
    def __init__(self, config, dns_resolver, is_local):
        self._config = config
        # 本地和远程采用同一份config文件，所以要区分
        if is_local:
            self._listen_addr = config['local_address']
            self._listen_port = config['local_port']
            self._remote_addr = config['server']
            self._remote_port = config['server_port']
        else:
            self._listen_addr = config['server']
            self._listen_port = config['server_port']
            self._remote_addr = None
            self._remote_port = None
        self._dns_resolver = dns_resolver
        self._password = config['password']
        self._method = config['method']
        self._timeout = config['timeout']
        self._is_local = is_local
        self._cache = lru_cache.LRUCache(timeout=config['timeout'],
                                         close_callback=self._close_client)
        self._client_fd_to_server_addr = \
            lru_cache.LRUCache(timeout=config['timeout'])
        self._eventloop = None
        self._closed = False
        self._last_time = time.time()
        self._sockets = set()

        addrs = socket.getaddrinfo(self._listen_addr, self._listen_port, 0,
                                   socket.SOCK_DGRAM, socket.SOL_UDP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" %
                            (self._listen_addr, self._listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)

        # server_socket是自己的socket
        server_socket.bind((self._listen_addr, self._listen_port))
        server_socket.setblocking(False)
        self._server_socket = server_socket

    def _get_a_server(self):
        server = self._config['server']
        server_port = self._config['server_port']
        if type(server_port) == list:
            server_port = random.choice(server_port)
        logging.debug('chosen server: %s:%d', server, server_port)
        # TODO support multiple server IP
        return server, server_port

    def _close_client(self, client):
        if hasattr(client, 'close'):
            self._sockets.remove(client.fileno())
            self._eventloop.remove(client)
            client.close()
        else:
            # just an address
            pass

    # 发到自己bind的端口的udp请求
    # 就只有可能是对方主动发送过来的，自己发送出去的udp请求要新建一个socket用来处理之后的请求
    def _handle_server(self):
        server = self._server_socket
        data, r_addr = server.recvfrom(BUF_SIZE)
        if not data:
            logging.debug('UDP handle_server: data is empty')
        if self._is_local:
            # 如果是local收到，那就是
            frag = common.ord(data[2])
# this is no classic UDP
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+
            if frag != 0:
                logging.warn('drop a message since frag is not 0')
                return
            else:
                data = data[3:]
                # [3:]之后变成
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+
# 就是shadowsocks那段
        else:
            # 如果是远程收到
            data = encrypt.encrypt_all(self._password, self._method, 0, data)
            # decrypt data
            if not data:
                logging.debug('UDP handle_server: data is empty after decrypt')
                return
        header_result = parse_header(data)
        if header_result is None:
            return
        addrtype, dest_addr, dest_port, header_length = header_result

        if self._is_local:
            # 如果是local收到，则server_addr server_port都是远程的
            server_addr, server_port = self._get_a_server()
        else:
            # 如果远程收到，则将server_addr这些改成dest_addr dest_port，方便操作
            server_addr, server_port = dest_addr, dest_port

        key = client_key(r_addr[0], r_addr[1], dest_addr, dest_port)
        client = self._cache.get(key, None)
        if not client:
            # TODO async getaddrinfo
            # 根据server_addr, server_port等的类型决定选用的协议类型
            # Translate the host/port argument into a sequence of 5-tuples
            addrs = socket.getaddrinfo(server_addr, server_port, 0,
                                       socket.SOCK_DGRAM, socket.SOL_UDP)
            if addrs:
                af, socktype, proto, canonname, sa = addrs[0]
                # 根据上面的server_addr, server_port建立相应的连接，一环扣一环
                # 这里是主动发出请求，所以要新建一个socket

                # 这里根据上面得到的不同的端口类型就新建不同类型的socket：用于tcp的和同于udp的
                client = socket.socket(af, socktype, proto)
                client.setblocking(False)
                self._cache[key] = client
                self._client_fd_to_server_addr[client.fileno()] = r_addr
            else:
                # drop
                return
            self._sockets.add(client.fileno())
            self._eventloop.add(client, eventloop.POLL_IN)

        if self._is_local:
            # 如果是local，要向远程发，要过墙，所以要加密
            data = encrypt.encrypt_all(self._password, self._method, 1, data)
            if not data:
                return
        else:
            # 如果是远程，要向dest发请求，所以把除数据的部分除去
            data = data[header_length:]
        if not data:
            return
        try:
            # 发送，完美无瑕。。。。
            # 这个sendto同时有udp的和tcp的两种，sendto函数主要用于UDP，但这里两种都用了
            client.sendto(data, (server_addr, server_port))
        except IOError as e:
            err = eventloop.errno_from_exception(e)
            if err in (errno.EINPROGRESS, errno.EAGAIN):
                pass
            else:
                logging.error(e)

    # 对于local，得到的是远程的相应，要往客户端发
    # 对于远程，得到的是dest的响应，要往local发
    def _handle_client(self, sock):
        data, r_addr = sock.recvfrom(BUF_SIZE)
        if not data:
            logging.debug('UDP handle_client: data is empty')
            return
        # 如果是远程
        if not self._is_local:
            addrlen = len(r_addr[0])
            if addrlen > 255:
                # drop
                return
            data = pack_addr(r_addr[0]) + struct.pack('>H', r_addr[1]) + data
            # 加密内容
            response = encrypt.encrypt_all(self._password, self._method, 1,
                                           data)
            if not response:
                return
        else:
            # 解密
            data = encrypt.encrypt_all(self._password, self._method, 0,
                                       data)
            if not data:
                return
            header_result = parse_header(data)
            if header_result is None:
                return
            # addrtype, dest_addr, dest_port, header_length = header_result
            response = b'\x00\x00\x00' + data

# 两个报文差3个字节的数据怎么办？加上去！客户端是有构造和识别SOCK5报文的能力的
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

            # 这里是真正的数据 
        client_addr = self._client_fd_to_server_addr.get(sock.fileno())
        if client_addr:
            # 同样的，完美无瑕。。
            self._server_socket.sendto(response, client_addr)
        else:
            # this packet is from somewhere else we know
            # simply drop that packet
            pass

    def add_to_loop(self, loop):
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop
        loop.add_handler(self._handle_events)

        server_socket = self._server_socket
        self._eventloop.add(server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR)

    def _handle_events(self, events):
        for sock, fd, event in events:
            if sock == self._server_socket:
                if event & eventloop.POLL_ERR:
                    logging.error('UDP server_socket err')
                # 处理来自server的udp消息
                self._handle_server()
            # shadowsocks可以给很多人用，所以可以有很多client socket
            elif sock and (fd in self._sockets):
                if event & eventloop.POLL_ERR:
                    logging.error('UDP client_socket err')
                # 处理来自client的udp请求
                self._handle_client(sock)

        now = time.time()
        if now - self._last_time > 3:
            self._cache.sweep()
            self._client_fd_to_server_addr.sweep()
            self._last_time = now
        if self._closed:
            self._server_socket.close()
            for sock in self._sockets:
                sock.close()
            self._eventloop.remove_handler(self._handle_events)

    def close(self, next_tick=False):
        self._closed = True
        if not next_tick:
            self._server_socket.close()
