# Runc config for NVIDIA devices

```
    {
        "destination": "/dev/vga_arbiter",
        "type": "bind",
        "source": "/dev/vga_arbiter",
        "options": [
            "rbind"
        ]
    },

    {
        "destination": "/dev/nvidia0",
        "type": "bind",
        "source": "/dev/nvidia0",
        "options": [
            "rbind"
        ]
    },
    {
        "destination": "/dev/nvidia1",
        "type": "bind",
        "source": "/dev/nvidia1",
        "options": [
            "rbind"
        ]
    },
    {
        "destination": "/dev/nvidiactl",
        "type": "bind",
        "source": "/dev/nvidiactl",
        "options": [
            "rbind"
        ]
    },
    {
        "destination": "/dev/nvidia-modeset",
        "type": "bind",
        "source": "/dev/nvidia-modeset",
        "options": [
            "rbind"
        ]
    },
    {
        "destination": "/dev/nvidia-uvm",
        "type": "bind",
        "source": "/dev/nvidia-uvm",
        "options": [
            "rbind"
        ]
    },
    {
        "destination": "/dev/nvidia-uvm-tools",
        "type": "bind",
        "source": "/dev/nvidia-uvm-tools",
        "options": [
            "rbind"
        ]
    },
    {
        "destination": "/dev/nvidia-caps",
        "type": "bind",
        "source": "/dev/nvidia-caps",
        "options": [
            "rbind"
        ]
    },
        
```
