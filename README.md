# F5-Migration
Migration script from F5 to Alteon

- [Corrently Supported](#corrently-supported)
- [Planed In The Future](#planed-in-the-future)
- [Usage](#usage)
  * [Running Locally](#running-locally)
  * [Using flask](#using-flask)
  * [Using Docker container](#using-docker-container)

## Corrently Supported ##
* Vlan ( requeres "Bigip_base.conf")
* Layer3 interfaces - SelfIP ( requeres "Bigip_base.conf" )
* Reals - Node ( requeres "Bigip.conf")
* Groups - Pool ( requeres "Bigip.conf")
* Health Checks - Monitor ( requeres "Bigip.conf")
* Virts ( requeres "Bigip.conf")
* Persistence ( requeres "Bigip.conf")
* Management ( requeres "Bigip_base.conf")
* Trunks / LACP ( requeres "Bigip_base.conf")
* Static Routes ( requeres "Bigip_base.conf")
* syslog ( requeres "Bigip_base.conf")
* NTP ( requeres "Bigip_base.conf")
* SNMP ( requeres "Bigip_base.conf")
* Filters transletion from Virt ( requeres only "Bigip.conf")

## Planed In The Future ##
* iRules
* Dynamic Routes
* Text modification ( transletion from stream profile )
* HA / Redundency
* Route Domains / Partitions
* GTM / Link Controller ( Link Proof / GSLB )

## Usage ##
### Running Locally ###
Use the following components :
1) local_runner.py
2) f5_Mig.py
3) app\global_variables.py ( Make sure to put the file in "app" directory )

Then run local_runner.py with "bigip.conf" file as an argument
To use more than one "bigip.conf" or "bigip_base.conf" file use $val$ as delimiter between files

For example : 
```
# python local_runner.py bigip.conf
```
Or
```
# python local_runner.py bigip.conf$val$bigip_base.conf
```

### Using flask ###
For webui environment download all the content of "app" directory and "browse.py" and install the following components on the server:
1. python3
2. python3-dev
3. pip
4. flask

To start flask use ( 8080 is the tcp port )
``` 
# python3 -m flask run --host=0.0.0.0 -p 8080
```

### Using Docker container ###
Download all git content ( only "local_runner.py" is not needed ), Then build and run the container

For example :
```
# git clone https://github.com/Radware/F5-Migration.git
# cd F5-Migration
# docker build -t f5_mig . && docker run -dit -p 8080:3011 --name f5_mig --restart on-failure f5_mig
```
