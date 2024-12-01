#!/usr/bin/env python3
import logging
from logging import handlers
import configparser
from io import StringIO
import json

import socket
import os
import time

logging.basicConfig(
    level=logging.INFO,
    handlers=[
        handlers.RotatingFileHandler(
            "mc_autostart.log", maxBytes=(1048576 * 2), backupCount=3
        ),
        logging.StreamHandler(),
    ],
    # minecraft-like logging format
    format="[%(asctime)s] [mc_autostart/%(levelname)s]: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger()


def load_config() -> dict:
    """Loads mc_autostart config into a dictionary.

    Returns:
        dict: config
    """
    with open("mc_autostart.json", "r") as config_file:
        config = json.load(config_file)
    return config


def load_properties() -> dict:
    """Loads server.properties into a dictionary.

    Returns:
        dict: server.properties
    """
    with open("server.properties", "r") as properties_file:
        # to use configparser with eula.txt and server.properties a section must be added
        # this section is added to the string
        properties_string = "[Config]\n" + properties_file.read()
    buf = StringIO(properties_string)
    config = configparser.ConfigParser()
    config.read_file(buf)
    return config._sections["Config"]


def sanity_check(
    config: dict,
    properties: dict,
):
    """Rudimentary check if the given configuration and server.properties can be used.

    Args:
        config (dict): mc_autostart.json config
        properties (dict): server.properties config

    Raises:
        TypeError: port in mc_autostart.json isn't a string
        Exception: both programms use the same port
        ValueError: shutdown_through_rcon is enabled in mc_autostart.json but rcon is disabled in server.properties
        KeyError: if shutdown_through_rcon is enabled but rcon.port or rcon.password are missing from server.properties
        ValueError: if shutdown_through_rcon is enabled but rcon.port or rcon.password have no value
    """
    if not isinstance(config["autostart_port"], str):
        logger.critical(
            "stopping mc_autostart! mc_autostart port must be given as a string!"
        )
        raise TypeError("mc_autostart port must be given as a string!")

    if config["autostart_port"] == properties["server-port"]:
        logger.critical(
            f"stopping mc_autostart! Minecraft Server Port {properties["server-port"]} MUST be different to mc_autostart port {config["autostart_port"]}."
        )
        raise Exception("ports must be different!")

    if config["shutdown_through_rcon"] and properties["enable-rcon"].lower() == "false":
        logger.critical(
            "stopping mc_autostart! shutdown_through_rcon is enabled, however rcon of minecraft server is disabled! Check server.properties"
        )
        raise ValueError(
            "rcon is enabled in mc_autostart but rcon is disabled in server.properties"
        )

    if config["shutdown_through_rcon"] and properties["enable-rcon"].lower() == "true":
        if "rcon.port" not in properties or "rcon.password" not in properties:
            logger.critical(
                "stopping mc_autostart! shutdown_through_rcon is enabled, however rcon.port or rcon.password are missing from server.properties"
            )
            raise KeyError("rcon.port or rcon.password missing from server.properties")
        elif properties["rcon.port"] == "" or properties["rcon.password"] == "":
            logger.critical(
                "stopping mc_autostart! rcon.port or rcon.password have no values set in server.properties"
            )
            raise ValueError("rcon.port or rcon.password have no value")


def read_varint(sock: socket) -> tuple[int, int]:
    """Read varint data type from connection that is min 1 and max 5 bytes long.

    Args:
        sock (socket): socket holding the connection

    Raises:
        ConnectionError: ConnectionError: If no byte can be read from the connection

    Returns:
        tuple[int, int]: received varint, byte length of varint
    """
    num = 0
    for i in range(5):  # 5 bytes limit
        byte = sock.recv(1)
        if not byte:
            raise ConnectionError("Connection closed by client")
        value = byte[0] & 0x7F
        num |= value << (7 * i)
        if not (byte[0] & 0x80):
            break
    return num, i + 1


def read_unsigned_short(sock: socket) -> tuple[int, int]:
    """Read unsigned short data type from connection.

    Args:
        sock (socket): socket holding the connection

    Returns:
        tuple[int, int]: received unsigned short, 2 (byte length of unsigned short)
    """
    byte = sock.recv(2)
    return int.from_bytes(byte, byteorder="big", signed=False), 2


def read_string(sock: socket) -> tuple[str, int]:
    """basic read_string function that reads the string size and returns the string.
    DOESN'T CHECK number of UTF-16 code units.
    If the string can't be parsed as UTF-8, the string will be skipped and an empty string will be returned instead.
    The bytes containing the string will be correctly skipped so following operations won't fail.

    Args:
        sock (socket): socket holding the connection

    Returns:
        tuple[str, int]: empty string on error or utf-8 string, number of bytes that where read
    """
    # string start with varint of length
    string_len, i = read_varint(sock)
    byte = sock.recv(string_len)
    try:
        ret_string = str(byte, "utf-8")
    except Exception as e:
        logger.error(f"couldn't parse string '{byte}' - skipping it")
        ret_string = ""
    return ret_string, string_len + i


def handle_server_list_ping(sock: socket):
    # Create the JSON response
    json_response = {
        "version": {"name": "1.21.1", "protocol": 767},
        "players": {"max": 0, "online": 0, "sample": [{"id": "1", "name": "nmcli"}]},
        "description": {
            "text": f"§6Server §7is currently §coffline§7.\n§a▶ Join to start the server."
        },
    }

    # Convert the JSON object to a string
    json_str = json.dumps(json_response)

    # Encode the JSON string as bytes
    json_bytes = json_str.encode("utf-8")

    # Prefix the JSON string with its length (VarInt)
    json_length = encode_varint(len(json_bytes))

    # Construct the status response packet
    packet_id = b"\x00"  # Status response packet ID
    packet_data = json_length + json_bytes  # Length of JSON + JSON string

    # Packet length (VarInt) - total length of the packet, including packet ID and all fields
    packet_length = encode_varint(len(packet_id) + len(packet_data))

    # Send the entire packet (length + packet ID + data) to the client
    sock.sendall(packet_length + packet_id + packet_data)
    print("Sent status response to the client.")


def start_listening(
    server_port: str,
    kick_message: str,
    server_start_command: str,
    offline_motd_message: str,
    mc_version: str,
    protocol_version: int
):
    # create a tcp server socket
    addr = ("", int(server_port))
    if socket.has_dualstack_ipv6():
        dual_stack = True
        family = socket.AF_INET6
    else:
        logger.warning(
            "your system doesn't support IPv6! mc_autostart will only listen on IPv4."
        )
        dual_stack = False
        family = socket.AF_INET4

    # create_server sets SO_REUSEADDR on POSIX platforms
    with socket.create_server(
        (addr), family=family, dualstack_ipv6=dual_stack, reuse_port=False, backlog=5
    ) as server:
        logger.info(f"server is listening on port {server_port}...")
        while True:
            conn, addr = server.accept()
            logger.info(f"new connection from {addr}")
            try:
                # read initial packet length
                packet_length, _ = read_varint(conn)

                # read the packet id (expecting handshake)
                packet_id, len_packet_id = read_varint(conn)
                packet_length -= len_packet_id
                if packet_id != 0x00:
                    logger.warning(
                        f"got packet id {hex(packet_id)} which is not supported!"
                    )
                    conn.close()
                    continue

                # read protocol version (see https://wiki.vg/Protocol_version_numbers)
                client_protocol_version, len_client_protocol_version = read_varint(conn)
                packet_length -= len_client_protocol_version

                # read server address and port
                server_address, len_server_address = read_string(conn)
                port_number, _ = read_unsigned_short(conn)
                packet_length = packet_length - len_server_address - 2

                # read next state
                next_state, len_next_state = read_varint(conn)
                if len_next_state != packet_length:
                    logger.error(
                        "actuall packet size doesn't match expected packet size!"
                    )
                    conn.close()
                    continue

                logger.info(
                    f"client {addr} uses protocol version {client_protocol_version} and send packet with id {hex(packet_id)} to {server_address}:{port_number} with state {hex(next_state)}"
                )

                match next_state:
                    case 0x01:
                        logger.info("server ping received")
                        handle_server_list_ping(conn)
                    case 0x02:
                        logger.info("login request received")
                    case _:
                        logger.error(f"unknown next state received {hex(next_state)}")


                # if "x02" in str(remaining_data):  # handshake packet type
                #     # proceed to send a disconnect packet in response
                #     packet = create_kick_packet(
                #         # kick_message.format(
                #         #     server_name=server_name, discord_invite=discord_invite
                #         # )
                #         kick_message
                #     )
                #     conn.sendall(packet)
                #     if conn.fileno() != -1:
                #         conn.close()
                #         server.close()
                #         time.sleep(1)
                #         os.system(server_start_command)
                #     logger.info("What is this?")
                #     # os.system(f"python3 {__file__}")

                # elif "x03" in str(remaining_data):
                #     logger.info(f"possible transfer packet detected")
                #     packet = create_kick_packet(kick_message)
                #     conn.sendall(packet)
                #     if conn.fileno() != -1:
                #         conn.close()
                #         server.close()
                #     time.sleep(1)
                #     os.system(server_start_command)
                #     os.system(f"python3 {__file__}")

            except Exception as e:
                logger.critical(f"couldn't handle connection: {e}")

            conn.close()
            logger.info(f"connection closed with {addr}")


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
    message_bytes = json_message.encode("utf-8")

    packet_id = b"\x00"  # packet id for login disconnect
    packet_data = packet_id + encode_varint(len(message_bytes)) + message_bytes

    packet_length = encode_varint(len(packet_data))
    return packet_length + packet_data


if __name__ == "__main__":
    logger.info("started mc_autostart")
    config = load_config()
    properties = load_properties()

    sanity_check(config, properties)

    start_listening(
        server_port=config["autostart_port"],
        kick_message=config["kick_message"],
        server_start_command=config["server_start_command"],
        offline_motd_message=config["offline_motd_message"],
        mc_version=config["mc_version"],
        protocol_version=config["protocol_version"]
    )
