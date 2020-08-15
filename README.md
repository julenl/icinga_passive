# Icinga Passive Sender

## Quick start
Send metrics from arbitrary shell commands into an Icinga2 as easy as:

    ./icinga_passive_sender.py -s 'SERVICE_NAME' --host HOST_NAME -c "df |grep '/$' | awk '{print $3}'"

Or with preset commands:

    ./icinga_passive_sender.py -s 'SERVICE_NAME' --host HOST_NAME -p root_disk

Set warning and critical thresholds:

    ./icinga_passive_sender.py -s 'SERVICE_NAME' --host HOST_NAME -p root_disk --warn 200000000 --crit 220000000

## Description
Icinga2 monitoring platform has the option to perform the so called "passive"
checks. These are little metrics collected within the target machine itself
and sent to Icinga2 via REST API.

This tool allows us to collect an send those metrics and send them to the 
Icinga2 REST API as passive data in a convenient way, without worrying about the request syntax.

It is specially useful in cases where we cannot (don't want to) install any client on the target machine and we do not want to write our own *Command + REST API* wrapper. In fact, this whole tool is just (AFAIK) the easiest tool to send the STDOUT of a shell command to the Icinga2 API.

## Icinga2 Server setup

### API user
First of all, make sure that *api* feature is enabled in `icinga2 feature list`.

We need a user to communicate with the Icinga2 API. For best practices, we can create an special API user to perform these passive check uploads, with just the single required permission to upload the data.

For that, we can include the following block into `/etc/icinga2/conf.d/api-users.conf`:

    object ApiUser "passive" {
        permissions = [ "actions/process-check-result" ]
        password = "WRITE_SOME_GOOD_PASSWORD_HERE"
    }

... and off course, after every configuration change, reload the *icinga2* service.
     
This way, if the credentials get compromised, in theory, the worst thing that could happen is that someone overloads or system with useless data.

### Passive service
The most common Icinga services are usually *active* ones, which means that the Icinga server triggers locally some plugin (script or executable), which collects some information about some given host.

If we want to collect information from inside a target host, we can setup the "Icinga2 agent" on the target, and let Icinga2 server trigger the data collection plugin locally on the target. This is good for example, for checking CPU load, disk usage, ...

But what if for some reason, we cannot install the Icinga2 agent or some other supported client on the target host? ... In that case, we can still inject our information directly onto the Icinga2 server by using a *passive service*.

On a passive service, the Icinga server will have a "passive" role, and just wait to receive the information from somewhere else (i.e. the REST API).

Here is an example for a passive service configuration:

    template Service "passive-service" {
      import "generic-service"
      check_command = "passive"
      enable_active_checks = false
      enable_passive_checks = true
      check_interval = 1d
    }

It is just like a regular service, but it contains the *enable_passive_checks* set as *True* and the *check_command* is *passive* (from the ITL). I put a quite long *check_interval* in some cases, in order to avoid the service complaining because it did not get any update recently. 

Finally, just apply the service to some host, group or creative *assign* rule:

    apply Service "TEST service" {
      import "passive-service"
      assign where host.name == "WEB_SERVER"
    }


## Client setup
The client setup is straight-forward. It will need to have Python (2 or 3) installed (the tool works on both), and some basic shell from where to retrieve the actual information to gather.

The first time the tool is run, it will as for the login credentials and store them in *~/.icinga_api_creds*, as:

    ./icinga_passive_sender.py -s 'TEST service' --host WEB_SERVER -p root_disk
    Enter the API endpoint for Icinga2, for example:
      "https://icinga2.example.com:5665"
    Icinga2 endpoint: "https://icinga2.fritz.box:5665"
    Enter the username for the Icinga2 API: "passive"
    Enter the password for the Icinga2 API: "WRITE_THE_GOOD_PASSWORD_FROM_ABOVE"

After that, the current user on the (target) system, will be able to send data to the REST API. 

## Troubleshooting
There are many things that might go wrong. I figured out some of those and wrote an option *-t* or *--test* which will check the three most probably issues:

- Check the connect to the REST API:
    - Ensures the credentials are correct
    - Checks if we have minimum permissions to upload the data
- In case the API user has permissions to request host objects:
    - Check that the requested host is defined in the Icinga2 server
- In case the API user has permissions to request service objects:
    - Ensure that the given service exists, it is assigned to the target host and that it accepts passive data

## Command presets
The original idea was to provide a way to easily turn a command into an API request. But sometimes, comming up with a command to retrieve a given parameter might be tricky, so I wrote a file called *lib_presets.py* in which I wrote some convenient presets to use instead of custom commands.

Presets are a quick way to get a value by sacrifying flexibiilty. For example, for active checks, there is the `check_disk` plugin, with tons of options to chose disks, partitions, paths, ignores, ... Most of the times, I am happy to know how full is my root partition, so the *root_disk* preset will retrieve that (on Unix based systems).

In order to list the available presets:

    ./icinga_passive_sender.py -s 'TEST service' --host rasplex -p root_disk --list_presets
    - total_cpu:  Total percentage of CPU capacity used
     # grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage }'
    
    - lm_cpu_temp:  CPU temperature in Celsius from lm-sensors
     # sensors -u | grep -A1 'Package id 0:' |tail -1 | awk '{print $NF}'
    
    - root_disk:  The the amount of used bytes on the main/root partition
     # df |grep '/$' | awk '{print $3}'
    
    - total_mem:  Total memory RAM in "active" state
     # awk '/MemTotal/ {total=$2} /MemFree/ {free=$2} /Buffers/ {buffers=$2} $1 ~ /^Cache/ {cached=$2} /SReclaimable/ {reclaim=$2} /Shmem:/ {shmem=$2} END {printf "%.0f\n", ((total - free) - (buffers + cached)) / 1024}' /proc/meminfo

Which means, these two commands are the same:

    ./icinga_passive_sender.py -s 'TEST service' --host WEB_SERVER -c "df |grep '/$' | awk '{print \$3}'"

and

    ./icinga_passive_sender.py -s 'TEST service' --host WEB_SERVER -p root_disk
