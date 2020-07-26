# JackBNimBLE manufacturing image

This hex file is for users who want to try out JackBNimBLE as soon as possible, 
without needing to build it yourself, which requires the Newt tool. 
Please follow the instructions to load the firmware onto a nrf52840 development
 board.

```
$ nrfjprog -f nrf52 --program jackbnimble-mfgimg.hex --chiperase
$ nrfjprog -f nrf52 --reset
```

You can download `nrfjprog` from https://www.nordicsemi.com/Software-and-tools/Development-Tools/nRF-Command-Line-Tools

# How to build the above hex file
1. Clone ```mynewt-newt-mynewt_1_8_0_tag``` from https://github.com/apache/mynewt-newt.git
2. Apply a patch of https://github.com/apache/mynewt-newt/pull/391/commits/96899e5bf8bc894a9542b39fd91ba34492a4b0fd
3. Build `newt`, refer to https://github.com/apache/mynewt-newt/blob/master/INSTALLING.md
3. Execute the following commands (refer to https://mynewt.apache.org/latest/newt/command_list/newt_mfg.html for details):
```
    $ cd {JackBNimBLE root}/firmware
    $ newt build nrf52840_boot
    $ newt build jbnblehci
    $ newt create-image jbnblehci 0.0.1
    $ newt mfg create jbnblehci 0.0.1
```


