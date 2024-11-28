# Automatically start your minecraft server when someone joins

This is a lightweight python socket server that listens for connections on the port you set in the configuration file and starts your minecraft server when it detects one.

## Features
- Very lightweight
- Easy to configure
- Very user friendly
- Very customisable

## Planned features
- Allow more control over the server with lostworld-rewritten
- Ban blacklisted players and IPs from autostarting the server

## How to use
1. Create your mc_autostart.json file:
    ```
    {
        "sever_name": "your server's name",
        "server_start_command": "command to start your server / path to start script",
        "autostart_port": 26656,
        "discord_invite": "invite to your discord server",
        "kick_message": "a message to show on the client when you attempt to join",
        "motd_message": "a message to display to the client on the server list",

        "respect_whitelist": true,
        "auto_shutdown": true,
        "start_timeout": 300,
        "stop_timeout": 150,
        "minimum_time_online": 600,
        "current_dir": ".",

        "shutdown_through_sigterm": true,
        "shutdown_through_rcon": false,
        "rconcli_path": "path to rcon_cli"
    }
    ```
    Place the mc_autostart.py and mc_autostart.json in the root directory of your server. The script will pull settings like rcon port, rcon password and server port from the server.properties file.

    > [! Important]
    >
    > The autostart_port is the port that the client has to enter in their server browser to connect to the REAL minecraft server, however the real port in the server.properties file must be different!
    > mc_autostart won't write to the server.properties file.

  1. Start the server:
     ## On windows:
     `py server.py` OR `python server.py`
     ## On macOS:
     `python server.py` OR `python3 server.py`
     ## On Linux:
     `python server.py` OR `python3 server.py`

## Need any help?
Discord server: https://discord.gg/lostworld
Discord username: nmcli
