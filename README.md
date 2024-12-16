# Automatically start your minecraft server when someone joins

Basic script to launch your minecraft server when someone tries to join.

## Current Features
- Supports all client and server versions >= 1.7
- Auto shutdown via `stop` command on stdin or via `SIGTERM`
  - `SIGTERM` is only supported on Linux
- Discord Webhook notifications


## How to use
1. Create your mc_autostart.json file:
    ```
    {
        "server_start_command": "start command / start script",
        "kick_message": "kick message",
        "offline_motd_message": "motd",
        "fake_players": [
            {
                "id": "valid uuid of player",
                "name": "player name"
            }
        ],
        "respect_whitelist": true or false,
        "mc_version": "game version string",
        "protocol_version": 763 //(protocol_version of the server),
        "server_dir": "path to the server directory or . if mc_autostart is in the root dir", // server_start_command will be exectued in this dir
        "auto_shutdown": true or false, // if the server should shutdown if no players are online - if false mc_autostart exits after the mc server started - auto shutdown will only work if the reported players in the minecraft server list are real players!
        "auto_shutdown_via_sigterm": false, // set to false if you invoke java directly (server_start_command = java ...), set to true if you use a second script that starts the server AND that can handle SIGTERM (via trap, etc.), SIGTERM only works on Linux, on Windows the server will be forced killed after stop_timeout
        "start_timeout": 20, // seconds to give the server to start, the server will be force killed and sent to sleep if the timeout is exceeded
        "stop_timeout": 20, // seconds to give the server to stop, the server will be force killed and sent to sleep if the timeout is exceeded
        "minimum_time_online": 1, // how long the server should be at least online after waking up
        "stop_after": 1, // how long the server should stay online after the last player left
        "discord_webhook_notification": false, // if discord webhook notifications should be send
        "discord_webhook_url": "your webhook url"
    }

    ```
    Working example:
    ```
    {
        "server_start_command": "java -Xmx1024M -Xms1024M -jar server.jar nogui",
        "kick_message": "Thank you for joining!\u00A7r\n\u00A7aServer is now starting - come back in 3-4 Minutes.",
        "offline_motd_message": "Minecraft Server\u00A7r\n\u00A74The Server is sleeping! \u00A7aJoin to start.",
        "fake_players": [
            {
                "id": "d8d5a923-7b20-43d8-883b-1150148d6955",
                "name": "Test"
            }
        ],
        "respect_whitelist": false,
        "mc_version": "1.20.1",
        "protocol_version": 763,
        "server_dir": "./test_server",
        "auto_shutdown": true,
        "auto_shutdown_via_sigterm": false,
        "start_timeout": 300,
        "stop_timeout": 60,
        "minimum_time_online": 300,
        "stop_after": 300,
        "discord_webhook_notification": false,
        "discord_webhook_url": ""
    }

    ```
    
> [!IMPORTANT]
> mc_autostart.py and mc_autostart.json need to be in the same folder!.

2. If you use docker for your server, use `auto_shutdown_via_sigterm: true` and a custom script that catches the SIGTERM signal to stop the server. This way you can stop the mc server before the host system shutsdown.

3. Start the server:
    ### On windows:
    `py mc_autostart.py` OR `python mc_autostart.py`
    ### On macOS:
    `python mc_autostart.py` OR `python3 mc_autostart.py`
    #### On Linux:
    `python mc_autostart.py` OR `python3 mc_autostart.py`

**Need any help?** -> Create an issue
