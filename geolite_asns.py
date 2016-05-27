#!/usr/bin/python
# Copyright 2016 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Pulls down MaxMind GeoLite ASN lists into a single CSV expected by clerk.

Pulls down IPv4 and IPv6 ASN maps provided at
http://dev.maxmind.com/geoip/legacy/geolite/ and outputs them to STDOUT as a
single CSV file that's usable by clerk.
"""

# This product uses GeoLite data created by MaxMind, available from
# <a href="http://www.maxmind.com">http://www.maxmind.com</a>.

import csv
import StringIO
import urllib
import zipfile

V4_URL = 'http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum2.zip'
V6_URL = 'http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum2v6.zip'


def CSVFileFromURL(url):
  zf = zipfile.ZipFile(StringIO.StringIO(urllib.urlopen(url).read()))
  return csv.reader(zf.open(zf.namelist()[0]))


def V4IntToIPv6(v4):
  return '::' + '%04x:%04x' % (v4 >> 16, v4 & 0xffff)


def ASNFromCSV(cell):
  return int(cell.split(' ')[0][2:])


def main():
  """Download CSVs, output to single, combined CSV file."""
  for row in CSVFileFromURL(V4_URL):
    # V4 format is IP,IP,AS### maybe other stuff
    # where IPs are ints (10.1.1.1 is '167837953').
    ip_a_int, ip_b_int, asn = int(row[0]), int(row[1]), ASNFromCSV(row[2])
    print '%s,%s,%d' % (V4IntToIPv6(ip_a_int), V4IntToIPv6(ip_b_int), asn)
  for row in CSVFileFromURL(V6_URL):
    # V6 format is AS### maybe other stuff,IP,IP,CIDR
    # where IPs are human-readable IPv6 addresses ('2001::1234').
    print '%s,%s,%d' % (row[1], row[2], ASNFromCSV(row[0]))


if __name__ == '__main__':
  main()
