#!/usr/bin/env python3
import logging
from logging import handlers
import configparser
from io import StringIO
import json
import socket
import subprocess
import time
import signal
import http.client
import sys

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

#! GLOBAL CONFIG
MC_AUTOSTART_CONFIG = {}
SERVER_PROPERTIES = {}
WHITELIST = {}
server_started = False


def load_config() -> dict:
    """Loads mc_autostart config into a dictionary.

    Returns:
        dict: config
    """
    with open("mc_autostart.json", "r") as config_file:
        config = json.load(config_file)
    if config["server_dir"][-1] != "/":
        config["server_dir"] += "/"
    return config


def load_properties() -> dict:
    """Loads server.properties into a dictionary.

    Returns:
        dict: server.properties
    """
    with open(
        MC_AUTOSTART_CONFIG["server_dir"] + "server.properties", "r"
    ) as properties_file:
        # to use configparser with eula.txt and server.properties a section must be added
        # this section is added to the string
        properties_string = "[Config]\n" + properties_file.read()
    buf = StringIO(properties_string)
    config = configparser.ConfigParser()
    config.read_file(buf)
    return config._sections["Config"]


def load_whitelist() -> dict:
    """Loads the server whitelist into a dictionary.

    Returns:
        dict: whitelist - {} if no whitelist was found
    """
    whitelist = {}
    try:
        with open(
            MC_AUTOSTART_CONFIG["server_dir"] + "whitelist.json", "r"
        ) as whitelist_file:
            whitelist = json.load(whitelist_file)
    except FileNotFoundError:
        logger.error(
            "couldn't find whitelist.json, ignoring it - if respect_whitelist is enabled no user will be able to join!"
        )
    return whitelist


def sanity_check():
    """Rudimentary check if the given configuration and server.properties can be used."""
    if not "auto_shutdown" in MC_AUTOSTART_CONFIG:
        MC_AUTOSTART_CONFIG["auto_shutdown"] = False

    if "discord_webhook_notification" in MC_AUTOSTART_CONFIG:
        if (
            MC_AUTOSTART_CONFIG["discord_webhook_notification"]
            and MC_AUTOSTART_CONFIG["discord_webhook_url"] == ""
        ):
            logger.error(
                "discord_webhook_url is empty, won't send wbhook notifications"
            )
            MC_AUTOSTART_CONFIG["discord_webhook_notification"] = False
    else:
        MC_AUTOSTART_CONFIG["discord_webhook_notification"] = False


def send_discord_notification(message: str):
    """Sends a post request to the discord webbhook. Returns if discord notifications are set to False

    Args:
        message (str): message to send, if longer then 200 characters, will be shortend.
    """
    if MC_AUTOSTART_CONFIG["discord_webhook_notification"] == False:
        return
    if len(message) >= 200:
        message = message[:195] + "..."

    conn = http.client.HTTPSConnection("www.discord.com")
    headers = {"Content-type": "application/json"}
    body = {"content": message, "embeds": []}
    json_data = json.dumps(body)
    conn.request("POST", MC_AUTOSTART_CONFIG["discord_webhook_url"], json_data, headers)
    response = conn.getresponse()
    logger.info(f"send discord notification with return code: {response.getcode()}")


def read_varint(conn: socket) -> tuple[int, int]:
    """Read varint data type from connection that is min 1 and max 5 bytes long.

    Args:
        conn (socket): socket holding the connection

    Raises:
        ConnectionError: ConnectionError: If no byte can be read from the connection

    Returns:
        tuple[int, int]: received varint, byte length of varint
    """
    num = 0
    for i in range(5):  # 5 bytes limit
        byte = conn.recv(1)
        if not byte:
            raise ConnectionError("connection closed by client")
        value = byte[0] & 0x7F
        num |= value << (7 * i)
        if not (byte[0] & 0x80):
            break
    return num, i + 1


def read_varint_bytes(data: bytes) -> tuple[int, int]:
    """Read varint data type from bytes object.

    Args:
        data (bytes): bytes object starting with varint

    Returns:
        tuple[int, int]: varint, byte length of varint
    """
    num = 0
    for i in range(5):  # 5 bytes limit
        byte = data[i]
        value = byte & 0x7F
        num |= value << (7 * i)
        if not (byte & 0x80):
            break
    return num, i + 1


def read_unsigned_short(conn: socket) -> tuple[int, int]:
    """Read unsigned short data type from connection.

    Args:
        conn (socket): socket holding the connection

    Returns:
        tuple[int, int]: received unsigned short, 2 (byte length of unsigned short)
    """
    byte = conn.recv(2)
    return int.from_bytes(byte, byteorder="big", signed=False), 2


def read_unsigned_short_bytes(data: bytes) -> tuple[int, int]:
    """Like read_unsigned_short but for a bytes object.

    Args:
        data (bytes): bytes object starting with the unsigned short!

    Returns:
        tuple[int, int]: unsigned short, 2 (byte length of unsigned short)
    """
    return int.from_bytes(data[:2], byteorder="big", signed=False), 2


def read_string(conn: socket) -> tuple[str, int]:
    """basic read_string function that reads the string size and returns the string.
    DOESN'T CHECK number of UTF-16 code units.
    If the string can't be parsed as UTF-8, the string will be skipped and an empty string will be returned instead.
    The bytes containing the string will be correctly skipped so following operations won't fail.

    Args:
        conn (socket): socket holding the connection

    Returns:
        tuple[str, int]: empty string on error or utf-8 string, number of bytes that where read (string + varint length)
    """
    # string start with varint of length
    string_len, i = read_varint(conn)
    byte = conn.recv(string_len)
    try:
        ret_string = str(byte, "utf-8")
    except Exception:
        logger.error(f"couldn't parse string '{byte}' - skipping it")
        ret_string = ""
    return ret_string, string_len + i


def read_string_bytes(data: bytes) -> tuple[str, int]:
    """Like read_string but for a bytes object

    Args:
        data (bytes): data starting with the varint length of the string

    Returns:
        tuple[str, int]: empty string on error or utf-8 string, number of bytes that where read (string + varint length)
    """
    string_len, i = read_varint_bytes(data)
    try:
        ret_string = str(data[i : i + string_len], "utf-8")
    except Exception as e:
        logger.error(f"couldn't parse string '{data[i:i + string_len]}' - skipping it")
        ret_string = ""
    return ret_string, string_len + i


def parse_packet(conn: socket) -> tuple[int, int, bytes]:
    """Parse a packet of the minecraft protocol consiting of length, id and data.
    Skipps data if packet only consists of length and id

    Args:
        conn (socket): socket holding the connection

    Raises:
        ValueError: if a legacy ping is detected

    Returns:
        tuple[int, int, bytes]: length, id, data (or empty byte string if no data is available)
    """
    packet_length, len_packet_length = read_varint(conn)
    if packet_length == 0xFE and len_packet_length == 2:
        # len_packet_length value of 2 is because of the way varints are parsed
        # https://wiki.vg/Server_List_Ping#1.6
        logger.error("received legacy ping")
        raise ValueError("not supported operation: legacy ping for version 1.6")
    packet_id, len_packet_id = read_varint(conn)
    if packet_length - len_packet_id == 0:
        data = b""
    else:
        data = conn.recv(packet_length - len_packet_id)
    return packet_length, packet_id, data


def get_raw_packet(conn: socket) -> bytes:
    """Parse a packet and returs raw bytes object containing packet length, id and data.

    Args:
        conn (socket): socket holding the connection

    Returns:
        bytes: full packet
    """
    packet_length, len_packet_length = read_varint(conn)
    data = int.to_bytes(packet_length, len_packet_length, "big")
    data += conn.recv(packet_length)
    return data


def parse_handshake_data(data: bytes) -> tuple[int, str, int, int]:
    """Parses a handshake data to it's fields

    Args:
        data (bytes): bytes object holding data for every handshake field

    Returns:
        tuple[int, str, int, int]: protocol version, server address, server port, next state
    """
    offset = 0
    client_protocol_version, len_client_protocol_version = read_varint_bytes(data)
    offset += len_client_protocol_version
    server_address, len_server_address = read_string_bytes(data[offset:])
    offset += len_server_address
    port_number, _ = read_unsigned_short_bytes(data[offset:])
    offset += 2
    next_state, _ = read_varint_bytes(data[offset:])
    return client_protocol_version, server_address, port_number, next_state


def encode_varint(value: int) -> bytes:
    """encodes an int as a varint.

    Args:
        value (int): value to encode

    Returns:
        bytes: varint representation of the int as a bytes object
    """
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


def encode_unsigned_short(value: int) -> bytes:
    """encoded an int as a unsigned short

    Args:
        value (int): value to encode

    Returns:
        bytes: bytes object of the short
    """
    return int.to_bytes(value, 2, "big", signed=False)


def add_length_field(data: bytes) -> bytes:
    """Adds the length field in front of the bytes object, useful for encoded strings and finished packets

    Args:
        data (bytes): data to add the length field to

    Returns:
        bytes: data starting with the length of the data as a varint
    """
    return encode_varint(len(data)) + data


def create_kick_packet(message: str = None) -> bytes:
    """creates the kick packet to be send to the client

    Args:
        message (str, optional): kick message. Defaults to MC_AUTOSTART_CONFIG["kick_message"].

    Returns:
        bytes: finished packet ready to be send
    """
    if message is None:
        message = MC_AUTOSTART_CONFIG["kick_message"]
    json_message = json.dumps({"text": message})
    message_bytes = json_message.encode("utf-8")

    packet_id = b"\x00"  # packet id for login disconnect
    packet_data = packet_id + encode_varint(len(message_bytes)) + message_bytes

    packet_length = encode_varint(len(packet_data))
    return packet_length + packet_data


def ping_mc_server() -> dict:
    """Ping the local mc server to check if it's online

    Returns:
        dict: {} if the server isn't available or the ping response if it's available
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        try:
            conn.connect(("localhost", int(SERVER_PROPERTIES["server-port"])))
            # Handshake: Packet ID 0x00 - Protocol Version 0x00 - host - port - next_state 0x01
            conn.send(
                add_length_field(
                    b"\x00\x00"
                    + add_length_field("localhost".encode("utf8"))
                    + encode_unsigned_short(int(SERVER_PROPERTIES["server-port"]))
                    + b"\x01"
                )
            )
            # Ping Request 0x00
            conn.send(add_length_field(b"\x00"))
            # Read response
            _, _, packet_data = parse_packet(conn)
            response, _ = read_string_bytes(packet_data)
        except Exception as e:
            logger.error(f"mc server unavailable, ping failed - {e}")
            response = "{}"
    return json.loads(response)


def handle_server_list_ping(conn: socket):
    """Handels the server list ping

    Args:
        conn (socket): socket holding the connection
    """
    # Awaiting Status Request with id 0x00 or ping request with id 0x01
    packet_length, packet_id, _ = parse_packet(conn)

    if not packet_id in [0x00, 0x01]:
        logger.warning(
            f"server ping handshake wasn't followed by correct request - got packet id {packet_id} instead"
        )
        return
    fake_players = MC_AUTOSTART_CONFIG["fake_players"]
    json_response = {
        "version": {
            "name": MC_AUTOSTART_CONFIG["mc_version"],
            "protocol": MC_AUTOSTART_CONFIG["protocol_version"],
        },
        "players": {
            "max": len(fake_players) + 1,
            "online": len(fake_players),
            "sample": fake_players,
        },
        "description": {"text": MC_AUTOSTART_CONFIG["offline_motd_message"]},
    }

    json_str = json.dumps(json_response)
    json_bytes = json_str.encode("utf-8")
    json_length = encode_varint(len(json_bytes))

    # Construct the status response packet
    packet_id = b"\x00"  # Status response packet ID
    packet_data = json_length + json_bytes  # Length of JSON + JSON string
    # Packet length (VarInt) - total length of the packet, including packet ID and all fields
    packet_length = encode_varint(len(packet_id) + len(packet_data))

    # Send the entire packet (length + packet ID + data) to the client
    conn.sendall(packet_length + packet_id + packet_data)
    logger.info("sending ping response to the client.")

    # The client may send an additional ping request to determine latency
    # This packet must be returned as is
    conn.sendall(get_raw_packet(conn))


def handle_player_join(conn: socket):
    """Handels the connection to a joining player, kicks them and executes the server_start_command.

    Args:
        conn (socket): socket holding the connection
    """
    # the login start request from the client must be received, or the kick message won't be displayed!
    _, _, data = parse_packet(conn)
    player_name, _ = read_string_bytes(data)
    logger.info(f"player {player_name} is trying to join the server")
    if MC_AUTOSTART_CONFIG["respect_whitelist"]:
        # the login request contains the name of the client, check if this name is on the whitelist
        # a cracked client or a bot could spoof the name to something on the whitelist
        # the server could start that way, however the actual minecraft server won't let them join
        if not any(player["name"] == player_name for player in WHITELIST):
            logger.info(
                f"player {player_name} is not on the whitelist - not starting the server"
            )
            conn.sendall(create_kick_packet("You are not whitelisted on this server"))
            return

    conn.sendall(create_kick_packet())
    send_discord_notification(f"Player {player_name} is waking up the server")
    logger.info(f"starting minecraft server...")
    global server_started
    server_started = True


def start_listening() -> any:
    """Listen to player connections, handle ping and login request and start server if player joins.


    Returns:
        any: The created subprocess of the server
    """
    addr = ("", int(SERVER_PROPERTIES["server-port"]))
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
        send_discord_notification("Server is sleeping and waiting for connections")
        logger.info(f"server is listening on port {addr[1]}...")
        while True:
            conn, client_addr = server.accept()
            conn.settimeout(10)
            logger.info(f"new connection from {client_addr}")
            try:
                # expecting handshake with id 0x00
                _, packet_id, data = parse_packet(conn)
                if packet_id != 0x00:
                    logger.warning(
                        f"expected handshake (0x00) but got packet id {hex(packet_id)} - closing connection!"
                    )
                    conn.close()
                    continue

                client_protocol_version, server_address, port_number, next_state = (
                    parse_handshake_data(data)
                )
                logger.info(
                    f"handshake from {client_addr} to {server_address}:{port_number} uses protocol version {client_protocol_version} with next_state {hex(next_state)}"
                )

                match next_state:
                    case 0x01:
                        logger.info("server ping received")
                        handle_server_list_ping(conn)
                    case 0x02:
                        logger.info("login request received")
                        handle_player_join(conn)
                        global server_started
                        if server_started:
                            if conn.fileno() != -1:
                                conn.close()
                            break
                    case _:
                        logger.error(f"unknown next state received {hex(next_state)}")

            except Exception as e:
                logger.critical(f"couldn't handle connection - {e}")

            conn.close()
            logger.info(f"connection closed with {client_addr}")
    logger.info("mc_autostart socket closed")
    p = subprocess.Popen(
        MC_AUTOSTART_CONFIG["server_start_command"].split(" "),
        shell=False,
        cwd=MC_AUTOSTART_CONFIG["server_dir"],
        stdin=subprocess.PIPE,
        text=True,
        bufsize=0,
    )
    return p


def wait_for_server() -> int:
    """Waits for the server to start, if the server is to slow (isn't available after start_timeout seconds) the server process is killed

    Returns:
        int: 0 on success, -1 if the timeout is exceeded
    """
    start_time = time.time()
    while True:
        # ping the server every ten seconds and check if the timeout is over / the server is available
        mc_status = ping_mc_server()
        if "players" in mc_status:
            return 0
        if time.time() - start_time > MC_AUTOSTART_CONFIG["start_timeout"]:
            return -1
        time.sleep(10)


def watch_server():
    """Watches the server for players and returns once the server should be shutdown"""
    start_time = time.time()
    last_online_time = 0
    while True:
        ping = ping_mc_server()
        if "players" not in ping:
            # server crashed
            logger.error("the minecraft server crashed - going back to sleep")
            send_discord_notification(
                "⚡ Minecraft Server crashed! Going back to sleep"
            )
            return
        player_number = ping["players"]["online"]
        if player_number > 0:
            last_online_time = time.time()
            logger.info(f"{player_number} players on server, not shuting down")
        else:
            current_time = time.time()
            logger.info(f"no players on server - checking if server should shutdown")
            if current_time - start_time > MC_AUTOSTART_CONFIG["minimum_time_online"]:
                # server is allowed to be shutdown
                if current_time - last_online_time > MC_AUTOSTART_CONFIG["stop_after"]:
                    logger.info(f"shuting down server")
                    send_discord_notification(
                        "🔴 No players on server, sending server to sleep"
                    )
                    return
        time.sleep(30)


def wait_for_server_shutdown() -> int:
    """Waits for the shutdown of the server, if the server is still running after stop_timeout.

    Args:
        server_process (any): the subprocess of the server

    Returns:
        int: 0 if the server is offline, -1 if the server is still running
    """
    shutdown_start = time.time()
    while True:
        if server_proccess.poll() is not None:
            # Server is gone
            return 0
        if time.time() - shutdown_start > MC_AUTOSTART_CONFIG["stop_timeout"]:
            # timeout exceted kill server
            return -1
        time.sleep(5)


def kill_server(server_process: any):
    # Fuck windows ;(
    if sys.platform == "win32":
        subprocess.call(
            ["taskkill", "/F", "/T", "/PID", str(server_proccess.pid)]
        )  # No world save
    else:
        # Not tested on mac
        server_proccess.kill()
    time.sleep(2)
    global server_started
    server_started = False


if __name__ == "__main__":
    logger.info("started mc_autostart")
    MC_AUTOSTART_CONFIG = load_config()
    SERVER_PROPERTIES = load_properties()
    sanity_check()
    WHITELIST = load_whitelist()

    if MC_AUTOSTART_CONFIG["auto_shutdown"]:
        while True:
            server_proccess = start_listening()
            logger.info(
                f"server_start_command send, PID of server: {server_proccess.pid} - watching server"
            )

            # Server is starting check if it's available
            status = wait_for_server()
            if status == -1:
                logger.critical(
                    "the server exceeded the start_timeout - killing the process and entering sleep mode"
                )
                send_discord_notification(
                    "Minecraft Server failed to start, going back to sleep"
                )
                kill_server(server_proccess)
                continue

            else:
                logger.info("mc server started successfully")
                send_discord_notification("🟢 Minecraft Server is running!")
                # wait until no more players are on the server
                watch_server()
                # server should shutdown wait for it
                try:
                    server_proccess.stdin.write(f"stop\n")
                    shutdown_status = wait_for_server_shutdown()
                    if shutdown_status == -1:
                        logger.error("server failed to shutdown - killing server")
                        send_discord_notification("server failed to shutdown")
                        kill_server(server_proccess)
                    else:
                        logger.info("server successfully shutdown")
                except Exception as e:
                    # if the server crashed the write command can't be executed
                    logger.error(f"couldn't send stop command - {e}")
                    shutdown_status = wait_for_server_shutdown()
                    if shutdown_status != 0:
                        # why is the process still running???
                        logger.warning(
                            "the mc server process is still running - killing it"
                        )
                        kill_server(server_proccess)

    else:
        server_proccess = start_listening()
        logger.info(
            f"server_start_command send, PID of server: {server_proccess.pid} - stopping mc_autostart"
        )
        send_discord_notification(
            "stopping mc_autostart because auto_shutdown is disabled"
        )
