# Dev container
A minimalistic, sandboxed container with networking that is fully contained within a folder.
The only dependency is [runc](github.com/opencontainers/runc). Docker is used to generate the rootfs but is not required for execution.

## Usage
Once bootstrapped, it is just a matter of running:

```
# Start the container
[user@host]$ ./run.sh 

# Login as a user (instead of root)
[root@dev]# ./start.sh
[user@dev]$ ...
```

You can use `firefox` to open a web browser, and `thunar` to open a file manager. You can also install any additional dependencies using the root terminal.
Additional terminals can also be created.

## How it works
Processes inside have no access to your host except through the specific bind mounted folders.
Container is set up with Linux namespaces, it is fully isolated with the exception of the bind mounts.

Access to the internet is provided via a domain socket.
The transparent proxy ensures network programs just work without needing do additional configuration.
GUI programs are supported by passing through a Wayland socket and setting the appropriate environmental variables.

This allows you have a full development environment contained within a single folder, with no file access other than what you have configured in `config.json`.

The set up looks like this
* `config.json` - [runc](github.com/opencontainers/runc) config
* `run.sh` - starts runc and the proxy server for networking
* `net/` - folder that is bind mounted into the container for networking
* `rootfs/` - runc rootfs (created by exporting a docker container)

Inside the container (inside `rootfs/root`):
* `net-conf.sh` - transparent proxy setup
* `nft.conf` - transparent proxy nft config
* `start.sh` - run as a user account

## Assumptions
Assumes you are running Wayland, and PulseAudio on your host Linux system.

## Bootstrapping
0. Clone the repo
```
git clone github.com/dogestreet/dev-container
```

1. Copy `config.template.json` into `config.json`
```
cp config.template.json config.json
```

2. Create rootfs for runc
```
mkdir rootfs/
docker export $(docker create archlinux:multilib-devel) | tar -C rootfs -xvf -
```

3. Compile `tproxy` on the host

```
cd tproxy
go build
```

4. Copy the network setup files into your roofs
```
cp files/* rootfs/root/
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

If you run `ip a`, you should only see a dummy network adapter.

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

You can also access any files directly on the host thru the `rootfs/` folder.
See `nvidia.md` for passing over NVIDIA graphics devices.

## About
The first shell that launches the container starts as `root`, the container has `no_new_privs` set. There is no root access except from this shell. If you drop your privs by running `start.sh`, you can Ctrl-D back out to become `root` again.
The `tproxy` program is flexible in that the domain socket is the only file that container needs for networking, you can put the other end of the `tproxy` in a more restrictive network sandbox if required.
