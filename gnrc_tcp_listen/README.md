# TCP listen

A small tool that uses GNRC TCP of RIOT to listen on a specific port. It can
handle a single connection at a time and simply prints all messages received.

## build and run

You can use this tool for testing on native Linux and macOS.
First, setup local networking for the test:

```
</path/to/riot>/dist/tools/tapsetup/tapsetup -c 1
```

Second, build and run the tcp_listen tool with RIOT on native.
Ensure that `RIOTBASE` is set or provide the path when calling `make`, like:

```
export RIOTBASE=</path/to/riot>
make && make term
```

Copy the lladdr of the RIOT node that is printed to the console and open another
terminal where you run _netcat_, as follows with the given port (default: 24911):

```
nc -6 <lladdr-of-riot>%bridge0 <port>
```

Now you can send strings from your host via _netcat_ to the RIOT node, which
prints the messages.

## debugging

You can use _wireshark_ or _tcpdump_ to sniff the network traffic, e.g.:

```
sudo tcpdump -i bridge0 tcp
```
