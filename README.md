Sets up a runc container with networking with folders bind mounted from the host

Container is set up with a process namespace, network namespace, etc.
Processes inside has no access to host except through the bind mounted folders.
Network is provided via a domain socket which the container uses by setting a transparent proxy.
GUI programs work by passing through a Wayland socket and setting environmental variables.

The set up looks like this
* `config.json` - runc config
* `run.sh` - runs runc and the proxy server
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

5. Start the container (`./run.sh`) without the "network" namespace and install utilities:

Remove this section:
```
    "linux": {
        "namespaces": [
            {
                "type": "pid"
            },
            {
                "type": "uts"
            },
            { <--- Remove this block
                "type": "network"
            },
            {
                "type": "mount"
            },
            {
                "type": "cgroup"
            }
        ],
```

```
[root@dev]# echo "nameserver 1.1.1.1" > /etc/resolv.conf
[root@dev]# pacman -Syu curl proxychains socat vim foot firefox git base-devel htop neovim zed llvm clang ripgrep fzf thunar fish iptables-nft foot-terminfo
```

6. Create a new user account (the script assumes it is named `user`) for yourself so you won't need to run as `root`.

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
            {
                "type": "network"
            },
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
[user@host] $ ./start.sh
[root@dev]# ./start.sh
[user@dev]$ 
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

## Usage
The first shell that launches the container starts as `root`, the container has `no_new_privs` set. There is no root access except from this shell. If you drop your privs by running `start.sh`, you can Ctrl-D back out to become `root` again.
The `tproxy` program is flexible in that the domain socket is the only file that container needs for networking, you can put the other end of the `tproxy` in a more restrictive network sandbox if required.
