# Mulroute
Mulroute is a multi destination IPv4/IPv6 traceroute for OS X and Linux. You can specify 
hosts as operands or write them to the standard input (whitespace separated).
Application uses raw sockets so it needs to be run in a privilidged mode.
**Warning**: IPv6 version has not been fully tested yet.

## Getting started
These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites
You need to have the following installed on your machine:
- **C++ compiler** with C++11 support
- **pthread** library

### Installation
First *clone* this repository and run *make*:
```
$  git clone https://github.com/romeritto/mulroute
$  make
```

An executable file `bin/mulroute` will be created. You can
symlink it into your `PATH` for an easier invocation.
```
$  (in the project root directory)
$  sudo ln -sf "$PWD"/bin/mulroute /usr/local/bin
```

#### Setting SUID
Note that `mulroute`, as well as other network utilities like `ping`, needs root
privilidges. In case of `ping`, the owner is set to `root` and the executable's `SUID`
bit is set. This step is optional and you should know what you are doing.
```
$  chmod u+s ./bin/mulroute
$  sudo chown root ./bin/mulroute
```

## Usage
The usage is very similiar to normal `traceroute`, but you can specify multiple hosts.
```
$  sudo mulroute google.com github.com
traceroute to google.com (172.217.16.110), 30 hops max
 1  nbg-416n (192.168.1.1)  1.875 ms  1.748 ms  1.724 ms
 2  10.10.10.1 (10.10.10.1)  2.288 ms  1.992 ms  2.006 ms
 3  192.168.201.65 (192.168.201.65)  3.354 ms  3.202 ms  3.051 ms
 (etc)

traceroute to github.com (192.30.253.112), 30 hops max
 1  nbg-416n (192.168.1.1)  1.790 ms  1.698 ms  1.735 ms
 2  10.10.10.1 (10.10.10.1)  2.131 ms  1.991 ms  2.049 ms
 3  192.168.201.65 (192.168.201.65)  3.355 ms  3.779 ms  3.420 ms
 (etc)
```

The hosts can be also read from the standard input:
```
$  sudo mulroute<Enter>
github.com
8.8.8.8
<Ctrl+D to stop the input>
```

Note that this might be used for tracerouting all hosts specified in a file:
```
$  sudo mulroute < sample_urls.txt
```

### Options
There are multiple options available. Run `sudo mulroute -h` to see the description.
```
$  sudo mulroute -h
usage: mulroute [46nh] [-f start_ttl] [-m max_ttl] [-p nprobes]
          [-z sendwait] [-w waittime] [host...]

Mulroute - multi destination ICMP traceroute. Specify hosts as operands
or write them to the standard input (whitespace separated). Application
uses raw sockets so it needs to be run in a privilidged mode.

Arguments:
  hosts                    Hosts to traceroute. If not provided, read
                           them from stdin.

Options:
  -h                       Show this message and exit
  -4                       If protocol of a host is unknown use IPv4 (default)
  -6                       If protocol of a host is unknown use IPv6
  -n                       Do not resolve IP addresses to their domain names
  -f start_ttl             Start from the start_ttl hop (default is 1)
  -m max_ttl               Set maximum number of hops (default is 30)
  -p nprobes               Set the number of probes per each hop (default is 3)
  -z sendwait              Wait sendwait milliseconds before sending next probe
                           (default is 10)
  -w waittime              Wait at least waittime milliseconds for the
                           last probe response (deafult is 500)
```

#### Examples of using the options
```
$  sudo mulroute -f 8 -m 13 google.com nah.com
```
Start with packets with TTL 8 and continue up to 13.

```
$  sudo mulroute -p 1 -n -z 50 rojk.nl slovakia.sk
```
Send only 1 probe per hop (TTL) and wait at least `50 ms` between sending each probe.
Also do not resolve IP addresses from received probes to domain names.

## Under the hood
The idea behind this traceroute utility is fairly simple. The app uses **two threads** -
one for *sending* the probes and one for *receiving*. 

### Sending
Every probe is an `ICMP Echo Request` packet which has its `ID` and `SEQ` fields set
according to the current destination, ttl and probe number. 

We start with TTL `start_ttl` and gradually send the probes with this TTL to every destination.

### Receiving
Using a `raw socket` we receive a copy of every `ICMP message` sent to the machine. These messages
contain 8 bytes of the original payload, which is enough for the original `ICMP Echo Request header`
that was sent. Based on `ID` and `SEQ` of this header we match received packet to the probe.

## Acknowledgments
I want to thank to **Mgr. Martin Mareš, Ph.D.** for the idea to make a multitraceroute utility and
**Adrián Király** for giving me a great suggestions.

## Contact me
If you find something unclear or if you have a suggestion, do not hesitate to write
me an email at r.sobkuliak(at)gmail.com
