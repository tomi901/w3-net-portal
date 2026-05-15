# Warcraft III Net Portal

A tool made to solve LAN not working when playing Warcraft III on Linux. Since for some reason
requests made by the game don't go through Wine or Lutris.

It forwards by sniffing broadcast UDP requests and forwarding them as unicast to selected peer IPs.
Only using requests to port 6112, the port Warcraft uses.

Additionally it allows LAN to work over VPNs or remote IPs.

## How to run

Using the executable cli, run `./w3-net-portal-cli -P [The other PC's IP to play with] -P [Optional additional IP for multiple devices]`

You can also add the `-v` argument to log additional info of forwarded data.

Leave this running on the background and you should be able to see the games running on the background. Usually, all linux
PCs will need this running using all peer IPs to ensure it's working.
