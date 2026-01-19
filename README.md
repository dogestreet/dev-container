# Dev container
Set up a development container with networking and folders bind mounted from the host.
The only dependency is [runc](github.com/opencontainers/runc) and docker is used to generate the rootfs but is not required for running.

Processes inside has no access to host except through the bind mounted folders.
Container is set up with a process namespace, network namespace, etc.
It is fully isolated except for the bind mounted folders that it shares with the host.

Networking is provided via a domain socket which the container uses by setting a transparent proxy.
The transparent proxy ensure programs just work without needing do additional configuration.
GUI programs work by passing through a Wayland socket and setting environmental variables.

The set up looks like this
* `config.json` - [runc](github.com/opencontainers/runc) config
* `run.sh` - starts runc and the proxy server for networking
* `net/` - folder that is bind mounted into the container for networking
* `rootfs/` - runc rootfs (created by exporting a docker container)

Inside the container (inside `rootfs/root`):
* `net-conf.sh` - transparent proxy setup
* `nfs.conf` - transparent proxy nft config
* `start.sh` - run as a user account

## Assumptions
Assumes you are running Wayland, and PulseAudio on your host Linux system.

## Bootstrapping
1. Copy `config.template.json` into `config.json`
```
[user@host]$ cp config.template.json config.json
```
2. Create rootfs for runc
```
[user@host]$ mkdir rootfs/
[user@host]$ docker export $(docker create archlinux:multilib-devel) | tar -C rootfs -xvf -
```
3. Compile `tproxy` on the host

```
[user@host]$ cd tproxy
[user@host]$ go build
```

4. Copy the network setup files into your roofs
```
[user@host]$ cp files/* rootfs/root/
```

5. Start the container without the "network" namespace and install utilities

Edit this section of `config.json`:
```
    "linux": {
        "namespaces": [
            {
                "type": "pid"
            },
            {
                "type": "uts"
            },
            {                       <---
                "type": "network"   <---  Remove this block
            },                      <---
            {
                "type": "mount"
            },
            {
                "type": "cgroup"
            }
        ],
```

```
[user@host]$ ./run.sh
[root@dev]# echo "nameserver 1.1.1.1" > /etc/resolv.conf
[root@dev]# pacman -Syu curl proxychains socat vim foot firefox git base-devel htop neovim zed llvm clang ripgrep fzf thunar fish iptables-nft foot-terminfo
```

6. Create a new user for yourself so you won't need to run as `root`.

```
[root@dev]# useradd -m user
```

7. If you need to spawn more terminals from inside the container you can run `foot fish &>/dev/null & disown`.
I recommend creating a script for it

```
[root@dev]# echo 'foot fish &>/dev/null & disown' > /usr/bin/spawn
[root@dev]# chmod +x /usr/bin/spawn
```

8. Ctrl-D out of there and add the "network" namespace back into your runc config.

Add this back in:
```
    "linux": {
        "namespaces": [
            {
                "type": "pid"
            },
            {
                "type": "uts"
            },
            {                      <---
                "type": "network"  <--- Add this back
            },                     <---
            {
                "type": "mount"
            },
            {
                "type": "cgroup"
            }
        ],
```

9. Container is ready to use

```
[user@host]$ ./run.sh
[root@dev]# ./start.sh
[user@dev]$ 
```

If you run `ip a`, you should only see the dummy adapter.

```
[user@dev]$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host proto kernel_lo 
       valid_lft forever preferred_lft forever
2: dummy0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN group default qlen 1000
    link/ether 36:db:e6:6f:29:ae brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.1/24 scope global dummy0
       valid_lft forever preferred_lft forever
    inet6 fe80::34db:e6ff:fe6f:29ae/64 scope link proto kernel_ll 
       valid_lft forever preferred_lft forever
```

## Customisation
Add any work folders to the container by adding more bind mounts to your config:

```
    {
        "destination": "/home/user/blah",
        "type": "bind",
        "source": "PATH ON HOST",
        "options": [
            "bind"
        ]
    }
```
You can also access any files directly on the host thru `rootfs/` folder.
See `nvidia.md` for passing over NVIDIA graphics devices.

## Usage
The first shell that launches the container starts as `root`, the container has `no_new_privs` set. There is no root access except from this shell. If you drop your privs by running `start.sh`, you can Ctrl-D back out to become `root` again.
The `tproxy` program is flexible in that the domain socket is the only file that container needs for networking, you can put the other end of the `tproxy` in a more restrictive network sandbox if required.
