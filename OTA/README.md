The directory provides an instantiated BORG on the 5G Testbed.

# Requirements
## Software
- srsRAN 4G (UE)
- srsRAN Project (gnB)
- Open5GS (Core)

Open5GS is provided as a Docker image within the srsRAN project, following the official repository of the srsRAN Project.

## Hardware
- 2xUSRP B210
- GPSDO (Leo BODNAR preferred)


# Setup Instructions
## Setup srsRAN Project:
```sudo apt-get install cmake make gcc g++ pkg-config libfftw3-dev libmbedtls-dev libsctp-dev libyaml-cpp-dev```

From the project initial directory:

``` 
cd srsRAN_Project
mkdir build
cd build
cmake ../ 
make -j $(nproc)
```

## Setup srsRAN 4G:
`sudo apt-get install build-essential cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev`

From the project initial directory

```
cd srsRAN_4G
mkdir build
cd build
cmake ../
make
make test
```

# Running Instructions:
- Start the Open5GS Core:
```
cd ./srsRAN_Project/docker
docker compose up --build 5gc
```

- On the same computer, start the srsgNB: 
(*Assuming user is at project initial directory*)
```
cd srsRAN_Project/build/apps/gnb
sudo ./gnb -c ./gnb.yaml
```

- On the same/different computer, start the srsUE: 
(*Assuming user is at project initial directory*)
```
cd srsRAN_4G/build/srsue
sudo ./srsue -c ./ue.conf
```

**Note:** If you are using srsgNB and srsUE on the same computer, make sure the USRP device numbers are properly input in the conf/yaml files.
The provided conf/yaml files contain USRP device numbers that needs to be modified.
