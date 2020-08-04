# JackBNimBLE

Current release version can only sends arbitrary advertising LL packets because I have not yet ported the LL control packet sending code from my fuzzer but I will port them soon.

## JBN Frimware

I encourage the users to be familiar with the [Apache Mynewt](https://mynewt.apache.org/) and its Bluetooth Low Energy stack [NimBLE](https://mynewt.apache.org/latest/tutorials/ble/ble.html)  and the [Newt](https://mynewt.apache.org/latest/newt/) tool if you want to build JackBNimBLE from the source code.  I used [mynewt-newt-mynewt_1_8_0_tag](https://github.com/apache/mynewt-newt/tree/mynewt_1_8_0_tag) to snapshot NimBLE and modify it.

However, if you want to take a short-cut, I have already created a binary for you as well, stored in [firmware-bin](https://github.com/darkmentorllc/jackbnimble/tree/master/firmware-bin)

### Prerequisites:
* nRF52840 Development Kit
* [nRF Command Line Tools](https://www.nordicsemi.com/Software-and-tools/Development-Tools/nRF-Command-Line-Tools)

Disable MSD mode
```
    $ JLinkExe
    J-Link>msddisable
```
## JBN Host

### Prerequisites:
* Python3
* [PyBlueZ](https://pybluez.readthedocs.io/en/latest/install.html) and its dependencies

Execute the following commands to install prerequisites on Ubuntu 18.04.4 LTS
```
    $ sudo apt install python3 python3-pip libbluetooth-dev
    $ pip3 install pybluez
```
Have a nRF52840 Development Kit with the JBN Firmware installer per the above, and connect it to a host via USB. Check `dmesg` to determine which ttyACM* device it is.
```
    $ dmesg | grep ACM | tail -n 1
    [1107771.736474] cdc_acm 3-2.4:1.0: ttyACM0: USB ACM device
```
Attach to the specified device.
```
    $ btattach -B /dev/ttyACM0 -S 1000000
    Attaching Primary controller to /dev/ttyACM0
    Switched line discipline from 0 to 15
    Device index 1 attached
```
Use the HCI interface ID ("Device index" listed above) as the -i argument to execute JBN Host. For example:
```
    $ ./jackbnimble.py -h
    $ sudo ./jackbnimble.py -i 1 ti_adv_rce crash
```
