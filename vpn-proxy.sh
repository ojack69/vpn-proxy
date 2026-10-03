#!/bin/bash

# Based on: https://blog.nviso.eu/2020/06/12/intercepting-flutter-traffic-on-ios/
# This script setups a Wireguard server docker container.
# The traffic on configured ports (REDIRECTED_TCP_PORTS - expecting HTTP/HTTPS traffic) will be redirected to the container's listening proxy.
# The main purpose of this script is to allow intercepting HTTP/HTTPs traffic during security assessment on Flutter applications.
# If using a non-Linux OS, this script will create a mitmproxy container in upstream mode; the VPN traffic will be forwarded to mitmproxy which will forward the HTTP/HTTPS traffic to the upstream (the proxy listening on the host). This is due to the fact that generally non-Linux OS use light VMs for Docker; in that case, iptables routing won't work.
# Alternatives: https://docs.mitmproxy.org/stable/concepts/modes/#wireguard

# Settings
VPN_SUBNET=10.80.80.0
VPN_UDP_PORT=51820 
VPN_PEER_DNS=1.1.1.1
REDIRECTED_TCP_PORTS="80,443"
LOCAL_INTERFACE="wlp1s0"
PROXY_PORT=8080 # needed when using mitmproxy
LOCAL_PORT=8080
LOCAL_HOST="$(ifconfig $LOCAL_INTERFACE | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"
CONTAINER_NAME="wg-proxy-vpn-server"

if [[ -n "$SUDO_USER" ]]; then
    CURRENT_USER="$SUDO_USER"
else
    CURRENT_USER="$USER"
fi
CONFIG_PATH="/home/$CURRENT_USER/.wg-proxy-vpn"

printf "
 __     ______  _   _   ____                      
 \ \   / /  _ \| \ | | |  _ \ _ __ _____  ___   _ 
  \ \ / /| |_) |  \| | | |_) | '__/ _ \ \/ / | | |
   \ V / |  __/| |\  | |  __/| | | (_) >  <| |_| |
    \_/  |_|   |_| \_| |_|   |_|  \___/_/\_\\__, |
                                            |___/ 

"

function log(){
    GREEN=$(tput setaf 2)
    RED=$(tput setaf 1)
    BLUE=$(tput setaf 6)
    NORMAL=$(tput sgr0)

    if [ "$2" == "success" ]; then
        echo -e "$GREEN[>] $NORMAL$1"
    elif [ "$2" == "error" ];then
        echo -e "$RED[x] $NORMAL$1"
    elif [ "$2" == "warning" ];then
        echo -e "$BLUE[!] $NORMAL$1"
    else
        echo -e "$1"
    fi
}

function get_config(){
    config_path="$CONFIG_PATH/config/peer1/peer1.conf"

    if [[ ! -f "$config_path" ]]; then
        log "VPN proxy not configured yet!" "error"
        exit 1
    fi

    log "Use the following client config file: $config_path" "warning"

    log "\n==========================================================="
    cat "$config_path" | sed -E 's/ListenPort = [0-9]+//g'
    log "\n==========================================================="

    qrencode_exist=$(which qrencode)
    if [[ -n "$qrencode_exist" ]];then
        log "\n==========================================================="
        cat "$config_path" | sed -E 's/ListenPort = [0-9]+//g' | qrencode -t ANSIUTF8 -m 2
        log "\n==========================================================="
    fi
}


# Action and Usage
action="$1"
if [[ "$action" != "start" && "$action" != "stop" && "$action" != "config" && "$action" != "uninstall" ]]; then
    log "Usage: $0 [start|stop|config|uninstall]"
    exit 1
fi


# Docker installed and running checks
check_docker_installed=$(which docker)
if [[ -z "$check_docker_installed" ]]; then
    log "Docker is not installed!" "error"
    exit 1
fi

check_docker_running=$(docker ps)

if [[ -z "$check_docker_running" ]]; then
    log "Docker is not running!" "error"
    exit 1
fi

# Wireguard container created and running checks
check_wireguard_container_exists=$(docker container ls -a | grep "$CONTAINER_NAME")

if [[ -z "$check_wireguard_container_exists" && "$action" == "start" ]]; then
    log "VPN container does not exists, creating it now..." "warning"
    
    mkdir -p "$CONFIG_PATH"

    # OS Checking
    if [[ "$(uname -s)" != "Linux" ]]; then
        log "Seems you are not running a Linux OS: re-routing the traffic to the listening proxy won't work since Docker it's likely to be running in a light vm." "warning"
        log "A mitmproxy instance in upstream mode will be used to bypass this restriction..." "warning"

        docker run --name "$CONTAINER_NAME-mitmproxy" -d mitmproxy/mitmproxy mitmdump --mode upstream:"http://$LOCAL_HOST:$LOCAL_PORT" -p "$PROXY_PORT" --set ssl_insecure=true 1>/dev/null 

        PROXY_HOST=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME-mitmproxy")
    else
        PROXY_HOST="$LOCAL_HOST"
        PROXY_PORT="$LOCAL_PORT"
    fi

    docker run -d --name="$CONTAINER_NAME" --cap-add=NET_ADMIN --cap-add=SYS_MODULE -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC -e SERVERURL="$LOCAL_HOST" -e PEERS=1 -e PEERDNS="$VPN_PEER_DNS" -e PERSISTENTKEEPALIVE_PEERS=25 -e INTERNAL_SUBNET="$VPN_SUBNET" -e ALLOWEDIPS=0.0.0.0/0 -e LOG_CONFS=true -p "$VPN_UDP_PORT":51820/udp -v "$CONFIG_PATH/config":/config -v /lib/modules:/lib/modules --sysctl="net.ipv4.conf.all.src_valid_mark=1" lscr.io/linuxserver/wireguard:latest 1>/dev/null

    check_wireguard_container_exists=$(docker container ls -a | grep "$CONTAINER_NAME")
    if [[ -z "$check_wireguard_container_exists" ]]; then
        log "Failed to create the wireguard server container!" "error"
        exit 1
    else
        log "Waiting for the server to setup..." "warning"
        sleep 3
        get_config
    fi
fi

if [[ "$action" == "start" ]];then
    
    log "Starting the VPN server container..." "success"
    docker container start "$CONTAINER_NAME" 1>/dev/null
    docker container start "$CONTAINER_NAME-mitmproxy" 1>/dev/null 2>/dev/null

    if [[ "$(uname -s)" != "Linux" ]]; then
        PROXY_HOST=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME-mitmproxy")
    else
        PROXY_HOST="$LOCAL_HOST"
        PROXY_PORT="$LOCAL_PORT"
    fi

    log "Setting up iptables..." "success"

    # Redirect TCP traffic on specified ports from VPN clients to host
    # -C (check) first so re-running 'start' doesn't keep appending duplicate rules
    docker exec "$CONTAINER_NAME" iptables -t nat -C PREROUTING -i wg0 -p tcp -m multiport --dports "$REDIRECTED_TCP_PORTS" -j DNAT --to-destination "$PROXY_HOST:$PROXY_PORT" 2>/dev/null ||
    docker exec "$CONTAINER_NAME" iptables -t nat -A PREROUTING -i wg0 -p tcp -m multiport --dports "$REDIRECTED_TCP_PORTS" -j DNAT --to-destination "$PROXY_HOST:$PROXY_PORT"

    # Allow forwarding
    docker exec "$CONTAINER_NAME" iptables -C FORWARD -i wg0 -p tcp -m multiport --dports "$REDIRECTED_TCP_PORTS" -d "$PROXY_HOST" -j ACCEPT 2>/dev/null ||
    docker exec "$CONTAINER_NAME" iptables -A FORWARD -i wg0 -p tcp -m multiport --dports "$REDIRECTED_TCP_PORTS" -d "$PROXY_HOST" -j ACCEPT

    # Allow packets to get back to the client
    docker exec "$CONTAINER_NAME" iptables -t nat -C POSTROUTING -o wg0 -j MASQUERADE 2>/dev/null ||
    docker exec "$CONTAINER_NAME" iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE
    
    log "Expecting listening port $LOCAL_PORT on host $LOCAL_HOST. Remember to enable invisible proxying when using Burp!" "warning"
    log "Done!" "success"

elif [[ "$action" == "stop" ]]; then
    log "Stopping the VPN server container..." "success"
    docker container stop "$CONTAINER_NAME" 1>/dev/null
    docker container stop "$CONTAINER_NAME-mitmproxy" 1>/dev/null 2>/dev/null
    log "Done!" "success"
    exit 0

elif [[ "$action" == "uninstall" ]]; then
    read -p "$(log "Are you sure you want to uninstall? y/N: " "warning")" confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
    if [[ $EUID -ne 0 ]]; then
        log "Root privileges are required to uninstall"  "error"
        exit 1
    fi
    rm -rf "$CONFIG_PATH"

    docker container stop "$CONTAINER_NAME" 1>/dev/null
    docker container stop "$CONTAINER_NAME-mitmproxy" 1>/dev/null 2>/dev/null
    docker container rm "$CONTAINER_NAME" 1>/dev/null
    docker container rm "$CONTAINER_NAME-mitmproxy" 1>/dev/null 2>/dev/null
    
    log "Done!" "success"

else
    get_config
    exit 0
fi
