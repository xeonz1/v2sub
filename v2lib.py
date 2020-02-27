import base64
import json
import os
import subprocess
import sys
# import time
import requests
# import urllib
from v2ray import V2ray

v2rayConfigLocal = '/etc/v2ray/config.json'
testFileUrl = "http://cachefly.cachefly.net/10mb.test"
v2subConfigPath = os.path.expandvars('$HOME') + '/.v2sub.conf'
serverListLink = []
serverList = []


# decode base64 string
def decode(base64Str):
    base64Str = base64Str.replace('\n', '').replace('-', '+').replace('_', '/')
    padding = int(len(base64Str) % 4)
    if padding != 0:
        base64Str += '=' * (4 - padding)
    return str(base64.b64decode(base64Str), 'utf-8')


# detect if is SU
def isSU():
    if os.geteuid() != 0:
        print("Please run the script with 'sudo' command.\n")
        exit()


# redirect
def askFollowRedirect(json):
    isFollowRedirect = ''
    try:
        isFollowRedirect = input('是否使用透明代理（重启失效）？[y/n/exit]')
    except KeyboardInterrupt:
        exit()
    except BaseException:
        return json
    if isFollowRedirect == 'y':
        # 判断是否开启了ip转发
        ipForward = subprocess.check_output("cat /proc/sys/net/ipv4/ip_forward", shell=True)
        if ipForward == b'0\n':
            # 添加ip转发
            subprocess.call("sysctl -w net.ipv4.ip_forward=1", shell=True)
            subprocess.call("sysctl -p /etc/sysctl.conf", shell=True)
        ## 修改json的相关参数
        json['inbounds'].append({
            "port": 12345,
            "protocol": "dokodemo-door",
            "settings": {
                "network": "tcp,udp",
                "followRedirect": True
            },
            "tag": "followRedirect",
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls"]
            }
        })
        json['routing']['settings']['rules'].append({
            "type": "field",
            "inboundTag": ["followRedirect"],
            "outboundTag": "out"
        })
        for outbound in json['outbounds']:
            if outbound["protocol"] == 'vmess' or outbound["protocol"] == 'shadowsocks':
                outbound['streamSettings']['sockopt'] = {
                    "mark": 255
                }
        # 关闭之前的iptables转发
        closeIPTableRedirect()
        # 开启iptable转发
        openIPTableRedirect()
        return json
    elif isFollowRedirect == 'n':
        ipForward = subprocess.check_output("cat /proc/sys/net/ipv4/ip_forward", shell=True)
        if ipForward == b'1\n':
            # 添加ip转发
            subprocess.call("sysctl -w net.ipv4.ip_forward=0", shell=True, stdout=subprocess.DEVNULL)
            subprocess.call("sysctl -p /etc/sysctl.conf", shell=True, stdout=subprocess.DEVNULL)
        closeIPTableRedirect()
        return json
    else:
        return askFollowRedirect(json)


# open iptable redirect
def openIPTableRedirect():
    subprocess.call("iptables -t nat -N V2RAY", shell=True, stdout=subprocess.DEVNULL)
    subprocess.call("iptables -t nat -A V2RAY -d 192.168.0.0/16 -j RETURN", shell=True, stdout=subprocess.DEVNULL)
    subprocess.call("iptables -t nat -A V2RAY -d 172.16.0.0/16 -j RETURN", shell=True, stdout=subprocess.DEVNULL)
    subprocess.call("iptables -t nat -A V2RAY -d 10.0.0.0/16 -j RETURN", shell=True, stdout=subprocess.DEVNULL)
    subprocess.call("iptables -t nat -A V2RAY -p tcp -j RETURN -m mark --mark 0xff", shell=True,
                    stdout=subprocess.DEVNULL)
    subprocess.call("iptables -t nat -A V2RAY -p udp -j RETURN -m mark --mark 0xff", shell=True,
                    stdout=subprocess.DEVNULL)
    try:
        subprocess.call(
            "iptables -t nat -A V2RAY -p tcp --match multiport ! --dports 12345,1080,22 -j REDIRECT --to-ports 12345",
            shell=True, stdout=subprocess.DEVNULL)
    except BaseException:
        print('以存在相应规则!跳过!')
    subprocess.call("iptables -t nat -A OUTPUT -p tcp -j V2RAY", shell=True, stdout=subprocess.DEVNULL)


# close iptable redirect
def closeIPTableRedirect():
    subprocess.call("iptables -t nat -F V2RAY", shell=True, stdout=subprocess.DEVNULL)


# detect and install v2ray
def V2rayInstallation():
    if subprocess.call("systemctl is-enabled v2ray.service",
                       shell=True,
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL) == 1:
        if input('V2ray not installed yet. Install V2ray by official script?(y/n)') == 'y':
            print('Downloading official script...')
            subprocess.run("wget https://install.direct/go.sh", shell=True, stdout=subprocess.DEVNULL)
            print('Installing v2ray...')
            subprocess.check_call('bash go.sh', shell=True)
            print('Cleaning temporary files...')
            subprocess.run('rm -rf go.sh', shell=True)
            exit()
        else:
            print('Please install V2ray before run this script.')
            exit()


# add a subscription
def addSubcription():
    if len(sys.argv) == 3:
        subLink = sys.argv[2]
    else:
        print("Subscription format error")
        exit()

    subFile = open(v2subConfigPath, 'w')
    jsonConf={
        "Link": subLink,
        "last": -1,
    }
    subFile.write(json.dumps(jsonConf, indent=4))
    subFile.close()


# get the list of info of servers from a url
def getSubLists(urldata):
    print("\nFetching server URLs...。\n")
    _serverListLink = decode(requests.get(urldata).text).splitlines(False)

    for i in range(len(_serverListLink)):
        base64Str = _serverListLink[i].replace('vmess://', '')
        jsonstr = decode(base64Str)
        serverNode = json.loads(jsonstr)
        serverList.append('【' + str(i) + '】' + serverNode['ps'])
        v2Node = V2ray(serverNode['add'], int(serverNode['port']), serverNode['ps'], 'auto', serverNode['id'],
                       int(serverNode['aid']), serverNode['net'], serverNode['type'], serverNode['host'],
                       serverNode['path'], serverNode['tls'])
        serverListLink.append(v2Node)


# get the URL of subscription
def getSubcribeURL():
    # 本脚本的配置文件，目前的作用是仅存储用户输入的订阅地址，这样用户再次启动脚本时，就无需再输入订阅地址。
    # 预设的存储的路径为存储到用户的 HOME 内。
    # 获取订阅地址
    if not os.path.exists(v2subConfigPath):
        return ''

    subFile = open(v2subConfigPath, 'r')
    subLink = json.load(subFile)['link']
    subFile.close()
    return subLink


# switch to specified node
def switchNode(setServerNodeId):
    jsonObj = serverListLink[setServerNodeId].formatConfig()
    jsonObj = askFollowRedirect(jsonObj)
    json.dump(jsonObj, open(v2rayConfigLocal, 'w'), indent=2)
    print("\nRestart v2ray service……\n")
    subprocess.call('systemctl restart v2ray.service', shell=True)
    print('switch complete')
    print('Port protocol：socks5')
    print('Proxy ip: 127.0.0.1')
    print('Proxy port：1080')
    # record subscribe server choosed
    subFile = open(v2subConfigPath, 'rw')
    jsonConf = json.load(subFile)
    jsonConf["last"] = setServerNodeId
    subFile.write(json.dumps(jsonConf, indent=4))
    subFile.close()
    exit()


# ask for the node to switch to
def askForNode():
    subFile = open(v2subConfigPath, 'r')
    jsonConf = json.load(subFile)
    setServerNodeId = jsonConf["last"]
    subFile.close()
    while True:
        if setServerNodeId == -1:
            try:
                setServerNodeId = int(input("\nSwitch to which one："))
            except KeyboardInterrupt:
                exit()
            except BaseException:
                continue
        else:
            print("Server used last time:{}".format(setServerNodeId))
        subprocess.call('ping ' + serverListLink[setServerNodeId].ip + ' -c 3 -w 10', shell=True)
        inputStr = input('Use this one？[y/n/exit]  ')

        if inputStr == 'y':
            switchNode(setServerNodeId)
        elif inputStr == 'n':
            setServerNodeId = -1
            continue
        else:
            exit()
