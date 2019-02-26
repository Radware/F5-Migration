# F5-Migration

## Table Of Contents ###
- [Description](#description )
- [How To Use](#how-to-use )
  * [Using Windows Exe](#using-windows-exe)
  * [Running Manually Using Python](#running-manually-using-python)
  * [Using Docker container](#using-docker-container)
- [Currently Supported](#currently-supported)
- [Planed In The Future](#planed-in-the-future)

## Description ##
The following script is used to migrate F5 Bigip configuration to Alteon configuration.<br>
Manual use was tested on both Linux and windows client, Docker was tested only on Linux server<br>
Currently we only support BigIP version 11 and above (TMSH based)<br>
Supported Alteon versions are 32.0.0.0 and above (not tested on older versions)<br>
The script works with both "bigip.conf" and "bigip_base.conf" refer to [Currently Supported](#currently-supported) section for full 

## How To Use ##
### Using Windows Exe ###
Windows users can use <a href=https://github.com/Radware/F5-Migration/raw/master/WindowsRunner.exe>WindowsRunner.exe</a>, This version contain all required modules and there is no need for any prerequisites

### Running Manually Using Python ###
In order to use the script make sure you have installed python3
The script uses the following modules:
* re
* os
* datetime
* tarfile
* sys

Then run local_runner.py with "bigip.conf" file as an argument<br>
For example : 
```
# python local_runner.py bigip.conf
```
To use more than one "bigip.conf" or "bigip_base.conf" file use $val$ as delimiter between files<br>
For example : 
```
# python local_runner.py bigip.conf$val$bigip_base.conf
```

### Using Docker container ###
Download all git content ( only "local_runner.py" is not needed ),<br>
Then build and run the container

For example :
```
# git clone https://github.com/Radware/F5-Migration.git
# cd F5-Migration
# docker build -t f5_mig . && docker run -dit -p 8080:3011 --name f5_mig --restart on-failure f5_mig
```

## Currently Supported ##
* Vlan (Bigip_base.conf)
* Layer3 interfaces - SelfIP (Bigip_base.conf)
* Reals - Node (Bigip.conf)
* Groups - Pool (Bigip.conf)
* Health Checks - Monitor (Bigip.conf)
* Virts (Bigip.conf)
* Persistence (Bigip.conf)
* Management (Bigip_base.conf)
* Trunks / LACP (Bigip_base.conf)
* Static Routes (Bigip_base.conf)
* syslog (Bigip_base.conf)
* NTP (Bigip_base.conf)
* SNMP (Bigip_base.conf)
* Filters transletion from Virt (Bigip.conf)
* HA / Redundency (Bigip_base.conf)

## Planed In The Future ##
* iRules
* Dynamic Routes
* Text modification ( transletion from stream profile )
* Route Domains / Partitions
* GTM / Link Controller ( Link Proof / GSLB )
