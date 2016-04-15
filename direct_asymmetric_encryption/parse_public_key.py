import sys

from pgpdump import AsciiData, BinaryData

def prepend_zero_if_odd_length(hex_string):
	return hex_string.zfill(len(hex_string) + len(hex_string) % 2)

def convert_to_hex(decimal_string):
	return '{:X}'.format(decimal_string)

def main():
	data = AsciiData(sys.stdin.read())
	#data = BinaryData(sys.stdin.read())
	for packet in data.packets():
		#It is always the first one. TODO: Better check, if it really is the correct one. We could take the fingerprint.
		if packet.__class__.__name__ == "PublicSubkeyPacket":
			#print(packet)
			print(prepend_zero_if_odd_length(convert_to_hex(packet.modulus)))
			print(prepend_zero_if_odd_length(convert_to_hex(packet.exponent)))
			return

if __name__ == '__main__':
	main()
