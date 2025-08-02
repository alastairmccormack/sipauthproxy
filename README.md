Replace a SIP digest auth credentials in realtime with known credentials.
Useful if you don't know what the original password of a phone was.

Build
-

```shell
docker build -t sipauthproxy .
```

Run
-
```shell
docker run -it -p 5060:5060/udp -e ASTERISK_SERVER=192.168.64.4:5060 -e PASS=newpassword sipauthproxy
```