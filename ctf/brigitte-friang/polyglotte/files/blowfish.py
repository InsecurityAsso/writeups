from Crypto.Cipher import Blowfish
from struct import pack

BS = Blowfish.block_size
KEY = b'\xce]`^+5w#\x96\xbbsa\x14\xa7\x0ei'
IV = b'\xc4\xa7\x1e\xa6\xc7\xe0\xfc\x82'

with open('message.pdf', 'rb') as f:
    file_data = f.read()
    
plen = BS - len(file_data) % BS
padding = [plen]*plen
padding = pack('b'*plen, *padding)
cipher = Blowfish.new(KEY, Blowfish.MODE_CBC, IV)
data = cipher.encrypt(file_data + padding)

with open('encrypted', 'wb') as f:
    f.write(data)

print('Success!')
