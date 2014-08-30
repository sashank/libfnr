#!/usr/bin/env python
import sys

"""
*    libFNR - A reference implementation library for FNR encryption .
*
*    FNR represents \"Flexible Naor and Reingold\" 

*    FNR is a small domain block cipher to encrypt small domain
*    objects ( < 128 bits ) like IPv4, MAC, Credit Card numbers etc.

*    FNR is designed by Sashank Dara (sadara@cisco.com), Scott Fluhrer (sfluhrer@cisco.com)
*
*    generate_ipv4.py has been written by Kaushal Bhandankar (kbhandan@cisco.com)
*
*    Copyright (C) 2014 , Cisco Systems Inc.
*
*    This library is free software; you can redistribute it and/or
*    modify it under the terms of the GNU Lesser General Public
*    License as published by the Free Software Foundation; either
*    version 2.1 of the License, or (at your option) any later version.
*
*    This library is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*    Lesser General Public License for more details.
*
*    You should have received a copy of the GNU Lesser General Public
*    License along with this library; if not, write to the Free Software
*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*
"""

def ipRange(start_ip, number):
    start = list(map(int, start_ip.split(".")))
    temp = start
    ip_range = []

    ip_range.append(start_ip)
    for i in range(1, number):
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1
        ip_range.append(".".join(map(str,temp)))    
    return ip_range

def main(argv):
    if(len(sys.argv) < 3):
        print "Usage: python generate_ipv4.py <start_ip_addr> <number_of_ips>"
        print "Eg: python generate_ipv4.py 192.168.1.1 5"
        return

    ip_range = ipRange(sys.argv[1], int(sys.argv[2]))
    f = open('raw-ips','w')
    f.write(sys.argv[2] + '\n')
    for ip in ip_range:
        f.write(ip + '\n')
    f.close()

if __name__ == "__main__":
    main(sys.argv[1:])
