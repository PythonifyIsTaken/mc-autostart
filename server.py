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


def start_listening(server_port: str, kick_message: str, server_start_command: str):
    # create a tcp server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", int(server_port)))
    server_socket.listen(5)

    logger.info(f"server is listening on port {server_port}...")

    while True:
        client_socket, address = server_socket.accept()
        logger.info(f"connection received from {address}")

        try:
            # read initial packet length
            packet_length = read_varint(client_socket)
            packet_id = client_socket.recv(
                1
            )  # read the packet id (expecting handshake)

            remaining_data = client_socket.recv(packet_length - 1)
            logger.info(f"Packet ID: {packet_id.hex()}")
            logger.info(f"Packet Data (Hex): {remaining_data.hex()}")
            logger.info(f"{remaining_data}")

            if "x02" in str(remaining_data):  # handshake packet type
                # proceed to send a disconnect packet in response
                packet = create_kick_packet(
                    # kick_message.format(
                    #     server_name=server_name, discord_invite=discord_invite
                    # )
                    kick_message
                )
                client_socket.sendall(packet)
                if client_socket.fileno() != -1:
                    client_socket.close()
                    server_socket.close()
                    time.sleep(1)
                    os.system(server_start_command)
                os.system(f"python3 {__file__}")

            elif "x01" in str(remaining_data):  # server ping request packet type
                logger.info(f"possible server list ping recieved:\n{remaining_data}")
                handle_server_list_ping(client_socket)

            elif "x03" in str(remaining_data):
                logger.info(f"possible transfer packet detected")
                packet = create_kick_packet(kick_message)
                client_socket.sendall(packet)
                if client_socket.fileno() != -1:
                    client_socket.close()
                    server_socket.close()
                time.sleep(1)
                os.system(server_start_command)
                os.system(f"python3 {__file__}")

            else:
                logger.info("Unexpected packet received")

        except Exception as e:
            logger.info(f"Error handling connection: {e}")

        client_socket.close()
        logger.info(f"Connection closed with {address}")


# read a varint
def read_varint(sock):
    num = 0
    for i in range(5):  # 5 bytes limit
        byte = sock.recv(1)
        if not byte:
            raise ConnectionError("Connection closed by client")
        value = byte[0] & 0x7F
        num |= value << (7 * i)
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


def handle_server_list_ping(client_socket):
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
    client_socket.sendall(packet_length + packet_id + packet_data)
    print("Sent status response to the client.")


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
    )
