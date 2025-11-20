from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "l.root-servers.net"    # ICANN Root Server
DNS_PORT = 53

# Cache dictionaries
cacheNS = {}
cacheA = {}
cacheAAAA = {}

def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
  print("\tConsulted " + parent_server)

  q = DNSRecord.question(domain, qtype = record_type)
  q.header.rd = 0   # Recursion Desired?  NO
  udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
  pkt, _ = udp_socket.recvfrom(8192)
  buff = DNSBuffer(pkt)
  
  """
  RFC1035 Section 4.1 Format
  
  The top level format of DNS message is divided into five sections:
  1. Header
  2. Question
  3. Answer
  4. Authority
  5. Additional
  """
  
  header = DNSHeader.parse(buff)
  #print("DNS header", repr(header))
  if q.header.id != header.id:
    #print("Unmatched transaction")
    return
  if header.rcode != RCODE.NOERROR:
    cacheA[domain] = "UNRECOGNIZED"
    return

  # Parse the question section #2
  for k in range(header.q):
    q = DNSQuestion.parse(buff)
    #print(f"Question-{k} {repr(q)}")

  # Parse the answer section #3
  for k in range(header.a):
    a = RR.parse(buff)
    #print(f"Answer-{k} {repr(a)}")
    if (a.rtype == QTYPE.AAAA and domain not in cacheAAAA):
      cacheAAAA[domain] = str(a.rdata)
    elif (a.rtype == QTYPE.A and a.rname and domain not in cacheA):
      cacheA[domain] = str(a.rdata)
      if (domain not in cacheNS):
        cacheNS[domain] = str(a.rname)

  # Parse the authority section #4
  for k in range(header.auth):
    auth = RR.parse(buff)
    #print(f"Authority-{k} {repr(auth)}")
    if (auth.rtype == QTYPE.NS and domain not in cacheNS):
      cacheNS[domain] = str(auth.rdata)
      
  # Parse the additional section #5
  for k in range(header.ar):
    adr = RR.parse(buff)
    #print(f"Additional-{k} {repr(adr)} Name: {adr.rname}")
    if (adr.rtype == QTYPE.AAAA and domain not in cacheAAAA):
      cacheAAAA[domain] = str(adr.rdata)
    elif (adr.rtype == QTYPE.A and adr.rname and domain not in cacheA):
      cacheA[domain] = str(adr.rdata)
      if (domain not in cacheNS):
        cacheNS[domain] = str(adr.rname)
  
if __name__ == '__main__':
  # Create a UDP socket
  sock = socket(AF_INET, SOCK_DGRAM)
  sock.settimeout(2)

  # Start main loop
  while True:
    fetch_flag = True
    domain_name = input("Enter a domain name or .exit > ")

    # Exit function
    if domain_name == '.exit':
      break

    # Clear function
    if domain_name == '.clear':
      fetch_flag = False
      cacheA = {}
      cacheNS = {}
      cacheAAAA = {}
      print("\tAll cache cleared.")

    # List function
    if domain_name == '.list':
      fetch_flag = False
      print("\tCached IPv4 Addresses: " + str(cacheA))
      print("\tCached Name Servers: " + str(cacheNS))
      print("\tCached IPv6 Addresses: " + str(cacheAAAA))

    # Remove function
    remove_tags = domain_name.split(" ")
    if remove_tags[0] == '.remove':
      fetch_flag = False
      try:
        del cacheA[remove_tags[1]]
        print("\tSuccessfully removed IP address from cache.")
      except:
        print("\tIP address not stored.")
      try:
        del cacheNS[remove_tags[1]]
        print("\tSuccessfully removed name server from cache.")
      except:
        print("\tName server not stored.")
      try:
        del cacheAAAA[remove_tags[1]]
        print("\tSuccessfully removed IPv6 address from cache.")
      except:
        print("\tIPv6 address not stored.")

    # Initiate DNS Search
    if (domain_name in cacheA):
      print("\t" + domain_name + ": " + cacheA[domain_name], end="")
      if (domain_name in cacheAAAA):
        print(", IPv6: " + cacheAAAA[domain_name] + " (saved in cache)")
      else:
        print(" (saved in cache)")
    else:
      # Request if not in cache
      while fetch_flag:
        name_chunks = domain_name.split(".")
        index_checking = -2
        # Loop backwards through request
        for word in reversed(name_chunks):
          domain_breakdown = word.split(".", 1)
          if (len(domain_breakdown) > 1): # If not a root request
              try:
                get_dns_record(sock, word, cacheNS[domain_breakdown[1]], "A")
                if (word not in cacheA and word in cacheNS): # If IP address is not found, request from given NS
                  get_dns_record(sock, word, cacheNS[word], "A")
              except (TimeoutError, KeyError): # If dnslib call timeouts
                cacheA[word] = "UNRECOGNIZED"
          else: # If root request
            try:
              get_dns_record(sock, word, ROOT_SERVER, "A")
            except TimeoutError: # If dnslib call timeouts
              cacheA[word] = "UNRECOGNIZED"
          if (-index_checking <= len(name_chunks)): # If not leftmost URL chunk
            name_chunks[index_checking] += "." + name_chunks[index_checking + 1]
            index_checking -= 1
          # Special result if name is unrecognized
          if (word in cacheA and cacheA[word] == "UNRECOGNIZED"):
            print("\t" + word + " unrecognized")
            del cacheA[word]
            break
        break

      # Print DNS Search Result
      if (fetch_flag):
        try:
          print("\t" + domain_name + ": " + cacheA[domain_name], end="")
          if (domain_name in cacheAAAA):
            print(", IPv6: " + cacheAAAA[domain_name])
          else:
            print()
        except KeyError:
          print("\tCould not retrieve IPv4 address for " + domain_name + ".")
  
  sock.close()