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
  1. Create your config.json file:  
```
{  
  "sever_name": "your server's name",  
  "server_start_command": "command to start your server",  
  "server_port": "your server's port",  
  "discord_invite": "invite to your discord server",  
  "kick_message": "a message to show on the client when you attempt to join",  
  "motd_message": "a message to display to the client on the server list"
}  
```
  2. Start the server:
     ## On windows:  
     `py server.py` OR `python server.py`  
     ## On macOS:
     `python server.py` OR `python3 server.py`
     ## On Linux:
     `python server.py` OR `python3 server.py`

## Need any help?
Discord server: https://discord.gg/lostworld
Discord username: nmcli
