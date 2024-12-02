# Automatically start your minecraft server when someone joins

Basic script to launch your minecraft server when someone tries to join.

## Current Features
- Supports all client and server versions >= 1.7

## Planned features
- Autoshutdown via SIGTERM or rcon

## How to use
1. Create your mc_autostart.json file:
    ```
    {
        "autostart_port": "25565",
        "server_start_command": "command to start your server",
        "kick_message": "a message to show on the client when you attempt to join",
        "offline_motd_message": "motd while the server is offline",
        "fake_players": [
            {
                "id": "VALID UUID -> if not valid, ping request won't work",
                "name": "Name of player to display in the server-list (set fake_players to [] to disable)"
            },
        ],
        "respect_whitelist": true or false,
        "mc_version": "1.20.1 game version of the server",
        "protocol_version": 763 (protocol_version of the server)
    }
    ```
    Working example:
    ```
    {
        "autostart_port": "25565",
        "server_start_command": "java -Xmx1024M -Xms1024M -jar server.jar nogui",
        "kick_message": "a message to show on the client when you attempt to join",
        "offline_motd_message": "motd while the server is offline",
        "fake_players": [],
        "respect_whitelist": false,
        "mc_version": "1.20.1",
        "protocol_version": 763
    }
    ```

> [!IMPORTANT]
> Place mc_autostart.py and mc_autostart.json in the root directory of your server. The script will pull settings from the server.properties file and the whitelist.

2. Start the server:
    ### On windows:
    `py mc_autostart.py` OR `python mc_autostart.py`
    ### On macOS:
    `python mc_autostart.py` OR `python3 mc_autostart.py`
    #### On Linux:
    `python mc_autostart.py` OR `python3 mc_autostart.py`

**Need any help?** -> Create an issue
