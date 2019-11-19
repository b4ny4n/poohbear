# poohbear
A very simple golang honeypot for home networks (eg. on a dedicated Raspberry Pi). Integrates with Amazon SES to alert on unexpected TCP connects.

```
                                                     #&&&?&/
                                                 #&&(,,,, .?,
                                               #&&,,,,,,,,.???&.    .&?&&.
                                               *?*,,,,,,,,?&  (??/(??#/&&?,
                                   (& &/      .&?/,,,,,,,,&?,,,,(&&&&,,,/??
                                  ,??*????&????(?&,,,,,,,(&,,,,,,,,(?/,,,(?&
                               .*?????#,.........,*,,,,,,,,,,,,,,,,,,,,,,,??
                             *????#...........,,,,,,,,,,,,,,,,,,,,,,,,,????
                           ??????,.........?*,,,,,,,,,,,,,,,,,,,,,,,,????
                       .?????/,,,,........??,*,,,,,,,,,,,,,,,,,,,,,,,#?(
                     ?????,,,,,,,,,,.,,,,,?#***,,,,,,,,,,,,,,,,,,,,,,*?/
                    ????,,,,,,,,,,,,,,**,*?#***,,,,,,,,,,,,,,,,,,,,,,*?/
                   ???,,,,,,,,,,,,,,,,****???**,,,,,,,,,,,,.....,,,,,/?/
                 ???*.,,,,,,,,,,,,,,,,*****??**,,,,,,,,,,........,,,,/?*
               (???,..,,,,,,,,,*,,,,(/*****??**,,,,,,,,,,........,,,,??
               /??,..,,,,,,,,,,*????(/,***/?#/?,,,,,,,,,,,......,,,,*?(
              (??*,,,**,,,,,,,,,,,.(???***#?*#?,,,,,,,,,,,.....,,,,.??.
             ???*,/***,,,,,,,,,,,,,,,.??#*#?*#?,,,,,,,,,,......,,,,*?#
           ?????#,****,,,,,,,,,,,,,,,,.??/*?(/?*,,,,#?#,./???????&???&???,
           ????.,******,,,*?#,,,,,,,,,,.??*.??#?#????&&&&(*,,,,,,,,,,,,. ??*
           ??#.***(&*,*(?,,&?(,,,,,,,,,,,??.?*&&&&?/***,,,,,,,*/(((/(#?#/ #?
          .??/*??*&*****???*&?*****,,,,,,(???(*&???#/(?&???&&&&&&&&&?#(/#&???&
          /&&&&**(/**,***&&&&&&*********,,,,&?&&&&///?&&&?#(////*********/&?((?#
          /&?****?**,,*?&?*#&&&&/**********,,,,#&&(&&&&&&?//#&&?#/***//,,&??/?#
          &&/****,,,,,*?/*#?*/&&&&**********,,,,,,,,/,,,#&&&(/**/////*/&&*,..&&
         .&&**,,,,,,,,,,*****/***&&&?********,,,,,,,,,,,,,&&?&&&?#(///,?&*,,,..?&
         ?&&&*,,,,,,,,,,,****///*/?&&&&&/****,,,,,,,,,,,,,,&&&&&&&&?/*,#&*,,,..&&
         &&*&,,,,,,,,,,,,*****//(////*/&&&&&,,,/,,,,,,,,*,,&&&(&?/(#?&&&&&&,,,&&.
        *&?*&,,,,,,,,,,,,,****///&&&///?&&&&??,*&/.?#,&&&&/&?&&&&&&?*,,&&&,
        #&(*&,,,,,,,,,,,,,,****///////#&&?/???&?&@@&&&&&&&&&&(/(&&&&&&?((/**(&(
        &&/&?,,*,,,,,,,,,,,*****///(&&&(//////@@&&&@@?##?&@&&&&??##(((##??&??##&&
        &&/,,**************#?#/*///////////*?@@@@@&&?##??&&&&&&&&&&&?#(((/***&& &&&/
        &&,&&&********//,**/&?&&&&&*********(&@@?&&@@@&?#?&&?&##??&&@&&**&&&?,,*?&?
        ?&/(#*&*****(&&&&/**********/&&&?***?&&&@@@&?&@&&&&&*,,&&&&@&&?????##(/&&(**#**#&,
         ?&&&*?#*/&&&************&&(***&&&&/&@@@@@@@@@&&&****&&&#?&@@&(((?&(/&***,&&
          ?&&&,&((&&/*********************?&&&@?@@@&??&&*/***/&?&&&??&&@@@@#&?,***&&,
...........&/&//&?&&*************************,?&@@@@?&(?*(?,&*&@&&?????&&&&?&&,?&***&&/..............
............&&&&(//&&&************************&**,/&&////&/**/&@&@@@&??????#&&******?&(..............
.............,&&&///&&&&?/**************************,,#?(/*(&**#&&?#?&&&&&??(/?*****?&(..............
...............,&&&//#&&&***?&&**&*******/&/**,,,,,,,*&*////*?/***&&?#((((#??&&&&/*&?***&&,..........
..................&&/&&&&&&(*(&&?****,,,,*&,,,,,,,?**///***/&&&&&&&&&&&&&&&&/&****...................
.....................?&&&&&&&&&?(&&(&&?*,&&&&?&&?,,,,,/**//?(****&&((&&&&/,,,,,,&&**?,#&&. ..........
                         *&&&&&&&&&&&*/,,/&(,*&&,,*,,*******(*&*.,/((#?&&&&&?&&&&&&(                 
                                 ../&&&&&&&&&&&&&&&,,?,,****#&*&&&&&&&&((/*,,......,
                                                 ,&&&&&?,,,&&&&&?
                                                     /&?&&&&&&&.
                                                         (#/.
```

## Poohbear Honey Pot

- A very simple honey pot for a home network
- Designed to alert for unanticipated scans/TCP connect attempts in the non-ephemeral range
- Configurable window to batch alerts into (avoids accidentally spamming yourself)
- Runs as a standalone binary (for example on a a Raspberry Pi) and sends email alerts 
- Sniffs TCP connection attempts on an interface using raw sockets without actually opening any ports  (adapted from https://github.com/bisrael8191/sniffer)
- Offers whitelisting for ports, MAC addresses, or MAC address + port combinations (ex. ssh from main machine into Pi)
- Basic de-duplication logic built in (only alerts for the same MAC -> port attempt once in a window, won't send an alert identical to the previous alert)

### Usage

#### Basic Usage

run with default configs, we see a recurring connect attempt to port 22, which only triggers an alert as a novel incident the first time:

```

me@Pi:~# ./poohbear -iface enp0s2 -email "bob@example.com"
2019/11/16 12:35:02
2019/11/16 12:35:02 ======================================
2019/11/16 12:35:02 Batch alert duration: 10m0s
2019/11/16 12:35:02 Using white list of ports: map[]
2019/11/16 12:35:02 Using white list of MACs: map[]
2019/11/16 12:35:02 Using white list of MAC|port combinations: map[]
2019/11/16 12:35:02 ======================================
2019/11/16 12:35:02
2019/11/16 12:35:02 Found requested interface. Using aa:bb:cc:dd:ee:ff
2019/11/16 12:35:07 Adding incident
(ff:ee:dd:bb:cc:aa@192.168.64.1) tried to connect on 192.168.64.6:22 at 2019-11-16 12:35:02.023856 -0700 MST
 now @ 1 incident(s)
2019/11/16 12:45:02 Alert Cycling
2019/11/16 12:45:03 Email Sent to address: bob@example.com
2019/11/16 12:45:03 Result: {
  MessageId: "0101016e75bf50aa-15a9e734-cfba-4667-9152-3be3936cb7b9-000000"
}
2019/11/16 12:45:07 Adding incident
(ff:ee:dd:bb:cc:aa@192.168.64.1) tried to connect on 192.168.64.6:22 at 2019-11-16 12:45:02.525636 -0700 MST
 now @ 1 incident(s)
2019/11/16 12:55:03 Alert Cycling
2019/11/16 12:55:03 Found 0 novel incidents
```



#### Whitelisting Options

The `-whitelist-macsports` switch allows filtering specific combinations:

```
me@Pi:~# ./poohbear -iface enp0s2 -email "bob@example.com" -whitelist-macsports "ff:ee:dd:cc:bb:aa|22"
2019/11/16 15:27:01 ======================================
2019/11/16 15:27:01 Batch alert duration: 10m0s
2019/11/16 15:27:01 Using white list of ports: map[]
2019/11/16 15:27:01 Using white list of MACs: map[]
2019/11/16 15:27:01 Using white list of MAC|port combinations: map[ff:ee:dd:cc:bb:aa:map[22:true]]
2019/11/16 15:27:01 ======================================
2019/11/16 15:27:01 
2019/11/16 15:27:01 Found requested interface. Using aa:bb:cc:dd:ee:ff
2019/11/16 15:27:06 Attempt from a whitelisted MAC:port, continuing
2019/11/16 15:27:06 Attempt from a whitelisted MAC:port, continuing
...
```

The `-whitelist-macs` and `-whitelist-ports` switches offer less granular filtering

Full help:

```
Usage of ./poohbear:
  -SES region string
        [OPTIONAL] AWS region for SES service, defaults to us-west-2 (default "us-west-2")
  -email string
        email address used for alerting
  -iface string
        interface to sniff. Defaults to eth0 (default "eth0")
  -interval string
        [OPTIONAL] interval for batching alerts together, (eg. 30s, 60m). Defaults to 10m (default "10m")
  -whitelist-macs string
        [OPTIONAL] CSV string of MAC addresses to never alert on (eg: aa:bb:cc:dd:ee:ff,a2:b2:c2:d2:e2:f2)
  -whitelist-macsports string
        [OPTIONAL] CSV string of MAC address|port combinations to never alert on (eg: aa:bb:cc:dd:ee:ff|8888)
  -whitelist-ports string
        [OPTIONAL] CSV string of ports to never alert on (eg: 22,80,443,8888)
```

#### Run as a service with systemd

To run poohbear as a service on Raspbian Linux, for example, put the following as root into `/etc/systemd/system/poohbear.service`

```
[Unit]
Description=Poohbear Honeypot
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/home/pi/go/src/poohbear/poohbear -email="bob@example.com" -whitelist-macsports="ff:ee:dd:bb:cc:aa|22"
User=root
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target

```

Then run `systemctl enable poohbear && systemctl start poohbear`

Logs can be viewed with `journalctl -u poohbear`


#### Integration with Amazon SES

Follow AWS instructions for setting up your account to send email (https://aws.amazon.com/ses/getting-started/). A simple strategy is to create an low-priv IAM user (can send emails only), and use the generated instance credentials, stored in `~/.aws/credentials`, where poohbear's SES integration will find and use the credentials to send the email. 

### Other Considerations

#### MAC Address

You may wish to make your honeypot blend better into the network.

Consinder the following arp-scan, in which the honeypot may appear suspicious to an attacker on your network:

```
arp-scan -l
Starting arp-scan 1.9.5 with 256 hosts (https://github.com/royhills/arp-scan)                      
192.168.1.1     db:7a:7b:3a:8:40       (Unknown)                                                                                                                                                      
192.168.1.118   b8:27:eb:18:e4:6c       Raspberry Pi Foundation                                    
192.168.1.133   a9:78:ab:2f:fb:45       (Unknown)                                                  
192.168.1.144   a0:8c:fd:22:17:e6       Hewlett Packard                                            
```

The Pi's mac address can be spoofed during network setup, so that it won't be clear what kind of device is replying to the arp-scan.

First, pick a random MAC address, for exmample with:

```
python -c 'import random; print(":".join(["{:x}".format(random.randint(0,256)) for i in range(6)]))'

# 69:b3:4f:fd:12:a4
```

Then put the resulting mac into the following stanza in /etc/network/interfaces for your target interface (example assuming 69:b3:4f:fd:12:a4 and eth0 below):

```
auto eth0
iface eth0 inet dhcp
    hwaddress ether 69:b3:4f:fd:12:a4
```

reboot your Pi and the new MAC should show up, not being readily identifiable as a Raspberry Pi to attackers.

#### Hostname

You may also wish to mask your hostname with something generic instead of the default `raspberrypi` that ships with Raspbian linux.
You can do so by editing /etc/hostname and rebooting.

