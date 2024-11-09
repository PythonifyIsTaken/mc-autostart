import socket
import json
import os

def load_config():
    with open('config.json', 'r') as config_file:
        config = json.load(config_file)
    return config

config = load_config()
server_name = config['server_name']
server_port = config['server_port']
discord_invite = config['discord_invite']
server_start_command = config['server_start_command']

# read a varint
def read_varint(sock):
    num = 0
    for i in range(5):  # 5 bytes limit
        byte = sock.recv(1)
        if not byte:
            raise ConnectionError("Connection closed by client")
        value = byte[0] & 0x7F
        num |= (value << (7 * i))
        if not (byte[0] & 0x80):
            break
    return num

# encode a varint
def encode_varint(value):
    out = bytearray()
    while True:
        temp = value & 0x7F
        value >>= 7
        if value != 0:
            temp |= 0x80
        out.append(temp)
        if value == 0:
            break
    return bytes(out)

# create a disconnect packet
def create_kick_packet(message):
    json_message = json.dumps({"text": message})
    message_bytes = json_message.encode('utf-8')

    packet_id = b'\x00'  # packet id for login disconnect
    packet_data = packet_id + encode_varint(len(message_bytes)) + message_bytes

    packet_length = encode_varint(len(packet_data))
    return packet_length + packet_data

# create a tcp server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', int(server_port)))
server_socket.listen(5)

print(f"Minecraft server is listening on port {server_port}...")

while True:
    client_socket, address = server_socket.accept()
    print(f"Connection received from {address}")

    try:
        # read initial packet length
        packet_length = read_varint(client_socket)
        packet_id = client_socket.recv(1)  # read the packet id (expecting handshake)

        if packet_id == b'\x00':  # handshake packet id
            # proceed to send a disconnect packet in response
            packet = create_kick_packet(f"Welcome to {server_name}! The server will be available shortly.\nWhile you wait, join {discord_invite}\n(server autostart successful)")
            client_socket.sendall(packet)
            os.system(server_start_command)
            if client_socket.fileno() != -1:
                client_socket.close()
                server_socket.close()
            os.system(f"python3 {__file__}")
            
        else:
            print("Unexpected packet received")

    except Exception as e:
        print(f"Error handling connection: {e}")

    client_socket.close()
    print(f"Connection closed with {address}")

