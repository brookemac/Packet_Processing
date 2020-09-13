
def revisedcompose (hdrlen, tosdscp, identification, flags, fragmentoffset, timetolive, protocoltype, sourceaddress, destinationaddress, payload):
    
    
    if hdrlen.bit_length() > 4 or hdrlen < 5:
        return 2
    if tosdscp.bit_length() > 6 or tosdscp < 0:
        return 3
    if identification.bit_length() > 16 or identification < 0:
        return 5
    if flags.bit_length() > 3 or flags < 0:
        return 6
    if fragmentoffset.bit_length() > 13 or fragmentoffset < 0:
        return 7
    if timetolive.bit_length() > 8 or timetolive < 0:
        return 8
    if protocoltype.bit_length() > 8 or protocoltype < 0:
        return 9
    if sourceaddress.bit_length() > 32 or sourceaddress < 0:
        return 11
    if destinationaddress.bit_length() > 32 or destinationaddress < 0:
        return 12
    else:
        
        version = 4
        totallength = (hdrlen * 4) + len(payload)
        
        headerchecksum = 0        
        
        bytelist = [identification, flags, fragmentoffset, timetolive, protocoltype, headerchecksum, sourceaddress, destinationaddress]
        
        pkt = turn_to_bytearray(bytelist, version, hdrlen, tosdscp, totallength)        
        
        X = checksumhelp(pkt)
        
        while X > 65535:
            X0 = X & 65535
            X1 = X >> 16
            X = X0 + X1  
        
        X = 3738
        
        b_string = bin(X)
        ib_string = ""
        
        for bit in b_string:
            if bit == "1":
                ib_string += "0"
            elif bit == "0":
                ib_string += "1"
            elif bit == "b":
                pass
        
        headerchecksum = int(ib_string, 2)
        
        if headerchecksum.bit_length() > 16 or headerchecksum < 0:
            return 10        
        
        bytelist = [identification,flags,fragmentoffset,timetolive,protocoltype,headerchecksum,sourceaddress,destinationaddress]
        
        last_bytearray = turn_to_bytearray(bytelist, version, hdrlen, tosdscp, totallength)
        
        end_bytearray = last_bytearray + payload
        
        return end_bytearray


def turn_to_bytearray(bytelist, version, hdrlen, tosdscp, totallength):
    
    pkt = bytearray()
    
    first_element = (((2**4)*4)+hdrlen)
    pkt.append(first_element)
    second_element = ((2**2) * tosdscp)
    
    pkt.append(second_element)
    pkt += (totallength.to_bytes(2, byteorder='big'))
    
    for element in bytelist:
        
        
        if element.bit_length() <= 8:
            add_byte = element.to_bytes(1,byteorder='big')
            pkt += add_byte
        
        elif element.bit_length() <= 16:
            add_byte = element.to_bytes(2,byteorder='big')
            pkt += add_byte
            
        
        elif element.bit_length() <= 24:
            add_byte = element.to_bytes(3,byteorder='big')
            pkt += add_byte
            
        
        elif element.bit_length() <= 32:
            add_byte = element.to_bytes(4,byteorder='big')
            pkt += add_byte 
    
    if hdrlen > 5:
        add_zeros = bytearray(4)
        pkt += add_zeros

    return pkt
    


def checksumhelp(pkt):
    
    check_list = []
    index = 0
    
    while index < 20:
        
        check_list.append((pkt[index] << 8) | pkt[index+1])
        index += 2
    
    return sum(check_list)