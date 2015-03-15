#!/usr/bin/env python3.4

import ctypes.util
from ctypes import *
from socket import AF_UNSPEC, AF_LINK, AF_INET, AF_INET6, inet_ntop
import json

class struct_sockaddr(Structure):
    _fields_ = [
        ('sa_len', c_ubyte),
        ('sa_family', c_ubyte),
        ('sa_data', c_byte * 14),
    ]

class struct_in_addr(Structure):
    _fields_ = [
        ('s_addr', c_uint),
    ]

class struct_sockaddr_in(Structure):
    _fields_ = [
        ('sin_len', c_ubyte),
        ('sin_family', c_ubyte),
        ('sin_port', c_ushort),
        ('sin_addr', struct_in_addr),
        ('sin_zero', c_byte * 8),
    ]

class struct_sockaddr_dl(Structure):
    _fields_ = [
        ('sdl_len', c_ubyte),
        ('sdl_family', c_ubyte),
        ('sdl_index', c_ushort),
        ('sdl_type', c_ubyte),
        ('sdl_nlen', c_ubyte),
        ('sdl_alen', c_ubyte),
        ('sdl_slen', c_ubyte),
        ('sdl_data', c_byte * 46),
    ]

class union_u6_addr(Union):
    _fields_ = [
        ('__u6_addr8', c_ubyte * 16),
        ('__u6_addr16', c_ushort * 8),
        ('__u6_addr32', c_uint * 4),
    ]

class struct_in6_addr(Structure):
    _fields_ = [
        ('__u6_addr', union_u6_addr),
    ]

class struct_sockaddr_in6(Structure):
    _fields_ = [
        ('sin6_len', c_ubyte),
        ('sin6_family', c_ubyte),
        ('sin6_port', c_ushort),
        ('sin6_flowinfo', c_uint),
        ('sin6_addr', struct_in6_addr),
        ('sin6_scope_id', c_uint),
    ]

class union_ifi_epoch(Union):
    _fields_ = [
        ('tt', c_int),
        ('ph', c_uint64),
    ]

class struct_timeval(Structure):
    _fields_ = [
        ('tv_sec', c_uint32),
        ('tv_usec', c_long),
    ]

class struct_ph(Structure):
    _fields_ = [
        ('ph1', c_uint64),
        ('ph2', c_uint64),
    ]

class union_ifi_lastchange(Union):
    _fields_ = [
        ('tv', struct_timeval),
        ('ph', struct_ph),
    ]

class struct_if_data(Structure):
    _fields_ = [
        ('ifi_type', c_uint8),
        ('ifi_physical', c_uint8),
        ('ifi_addrlen', c_uint8),
        ('ifi_hdrlen', c_uint8),
        ('ifi_link_state', c_uint8),
        ('ifi_vhid', c_uint8),
        ('ifi_datalen', c_uint16),
        ('ifi_mtu', c_uint32),
        ('ifi_metric', c_uint32),
        ('ifi_baudrate', c_uint64),
        ('ifi_ipackets', c_uint64),
        ('ifi_ierrors', c_uint64),
        ('ifi_opackets', c_uint64),
        ('ifi_oerrors', c_uint64),
        ('ifi_collisions', c_uint64),
        ('ifi_ibytes', c_uint64),
        ('ifi_obytes', c_uint64),
        ('ifi_imcasts', c_uint64),
        ('ifi_omcasts', c_uint64),
        ('ifi_iqdrops', c_uint64),
        ('ifi_oqdrops', c_uint64),
        ('ifi_noproto', c_uint64),
        ('ifi_hwassist', c_uint64),
        ('__ifi_epoch', union_ifi_epoch),
        ('__ifi_lastchange', union_ifi_lastchange),
    ]

class union_ifa_ifu(Union):
    _fields_ = [
        ('ifu_broadaddr', POINTER(struct_sockaddr)),
        ('ifu_dstaddr', POINTER(struct_sockaddr)),
    ]

class struct_ifaddrs(Structure):
    pass
struct_ifaddrs._fields_ = [
    ('ifa_next', POINTER(struct_ifaddrs)),
    ('ifa_name', c_char_p),
    ('ifa_flags', c_uint),
    ('ifa_addr', POINTER(struct_sockaddr)),
    ('ifa_netmask', POINTER(struct_sockaddr)),
    ('ifa_dstaddr', POINTER(struct_sockaddr)),
    ('ifa_data', c_void_p),
]

libc = ctypes.CDLL(ctypes.util.find_library('c'))

def get_family_addr(sin):
    family = sin.sa_family
    addr = None
    if family == AF_INET:
        sin = cast(pointer(sin), POINTER(struct_sockaddr_in)).contents
        addr = inet_ntop(family, sin.sin_addr)
    elif family == AF_INET6:
        sin = cast(pointer(sin), POINTER(struct_sockaddr_in6)).contents
        addr = inet_ntop(family, sin.sin6_addr)
    elif family == AF_LINK:
        sin = cast(pointer(sin), POINTER(struct_sockaddr_dl)).contents
        if sin.sdl_alen > 0:
            # name = [chr(x) for x in sin.sdl_data[0:sin.sdl_nlen]]
            addr = ':'.join(['%02x' % (x & 0xff) for x
                             in sin.sdl_data[sin.sdl_nlen:sin.sdl_nlen + sin.sdl_alen]])
    return family, addr

def get_if_data(data):
    retval = {}
    data = cast(c_void_p(data), POINTER(struct_if_data)).contents
    retval['ibytes'] = data.ifi_ibytes
    retval['obytes'] = data.ifi_obytes
    retval['ipackets'] = data.ifi_ipackets
    retval['opackets'] = data.ifi_opackets
    return retval

def get_if_addrs():
    ifap = POINTER(struct_ifaddrs)()
    if libc.getifaddrs(pointer(ifap)) == 0:
        retval = {}
        ifa = ifap.contents
        while True:
            name = ifa.ifa_name.decode('utf8')
            if not retval.get(name):
                retval[name] = {}
            family, addr = get_family_addr(ifa.ifa_addr.contents)
            retval[name][addr] = get_if_data(ifa.ifa_data)
            if not ifa.ifa_next:
                break
            else:
                ifa = ifa.ifa_next.contents

        libc.freeifaddrs(ifap)
        return retval

if __name__ == '__main__':
    print(json.dumps(get_if_addrs(), indent=4))
