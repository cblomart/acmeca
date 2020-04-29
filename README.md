# Down to earth ACME server

```bash
> acmeca --help     
NAME:
   server - Start ACME server

USAGE:
   acmeca [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --httpscert value          Certificate to use for HTTPS (default: "/etc/acmeca/certs/https.crt") [%HTTPS_CERT%]
   --httpskey value           Key to use for HTTPS (default: "/etc/acmeca/certs/https.pem") [%HTTPS_KEY%]
   --hostnames value          Hostname for self sign certificate (default: "localhost") [%HOSTNAMES%]
   --listen value             Address to listen to (default: ":8443") [%LISTEN%]
   --noncestorage value       Nonce storage type to use (default: "memory") [%NONCE_STORAGE%]
   --objectstorage value      Object storage type to use (default: "xorm") [%OBJECT_STORAGE%]
   --objectstorageopts value  Object storage options (key1=value1;key2=value2;...) [%OBJECT_STORAGE_OPTS%]
   --certstorage value        certificate storage type to use (default: "file") [%CERT_STORAGE%]
   --certstorageopts value    certificate storage options (key1=value1;key2=value2...) [%CERT_STORAGE_OPTS%]
   --domains value            allowed top level domains (default: ".local") [%DOMAINS%]
   --ca                       enable ca requests (default: false) [%CA%]
   --cacert value             CA certificate (default: "/etc/acmeca/certs/ca.crt") [%CACERT%]
   --cakey value              CA key (default: "/etc/acmeca/certs/ca.pem") [%CAKEY%]
   --acme                     enable acme requests (default: true) [%ACME%]
   --secret value             secret for communication with ca (picked from /run/secrets/acmesecret) [%SECRET%]
   --caurl value              url to ca (default: "https://localhost:8443/ca") [%CASERVER%]
   --cron                     cron tasks (default: true) [%ACMECRON%]
   --help, -h                 show help (default: false)
```

The server is designed to be flexible allowing:

* different backend storage for
  * certificates
  * configuration
  * nonces

It will also work in different modes:

* server: servers acme requests
* ca: generates certificates

This allows to secure the ca in a place only accessible by frontend servers.

# architectures

## single server

```ascii
file cert store  sqlite object store (xorm)
        |         |
       ++---------++
HTTPS  |           +--+
------>+ ACME + CA |  | CA requests
       |           +<-+
       +-----+-----+
             |
<------------+
ACME verifications
```

## signle server for acme and CA

```ascii
  sqlite object store (xorm)
             |
       +-----+-----+      +--------+
HTTPS  |           |      |        |
------>+    ACME   +----->+   CA   |
       |           |      |        |
       +-----+-----+      +----+---+
             |                 |
<------------+           file cert store
ACME verifications
```

## multiple frontends for acme and one CA

> **TODO**: have a distributed nonce store (xorm or redis). I personaly prefer redis

```ascii
ACME verifications
<-----------------+  
                  |
---+        +-----+-----+           
L  | HTTPS  |           |           
O  | ------>+    ACME   +-----------+
A  |        |           |           |
D  |        +-----+-----+           |     +--------+
B  |              |                 |     |        |
A  |   mariadb object store (xorm)  +---->|   CA   |
L  |   + redis nonce store          |     |        |
A  |              |                 |     +----+---+
N  |        +-----+-----+           |          |
C  | HTTPS  |           |           |   file cert store
E  | ------>+    ACME   +-----------+   
R  |        |           |           
---+        +-----+-----+           
                  |                      
<-----------------+               
ACME verifications
```

## multiple acme and ca

> **TODO**: implementing S3 certificate store would allow to loadbalance multiple CA servers

```ascii
ACME verifications
<-----------------+  
                  |
---+        +-----+-----+           +-----+     +--------+     +------------+
L  | HTTPS  |           |           |  L  |     |        |     |            |
O  | ------>+    ACME   +---------->+  O  +---->|   CA   +<--->+            |
A  |        |           |           |  A  |     |        |     |            |
D  |        +-----+-----+           |  D  |     +--------+     |            |
B  |              |                 |  B  |                    |            |
A  |   mariadb object store (xorm)  |  A  |                    |     S3     |
L  |   + redis nonce store          |  L  |                    |            |
A  |              |                 |  A  |                    |            |
N  |        +-----+-----+           |  N  |     +--------+     |            |
C  | HTTPS  |           |           |  C  |     |        |     |            |
E  | ------>+    ACME   +---------->+  E  +---->|   CA   +<--->+            |
R  |        |           |           |  R  |     |        |     |            |
---+        +-----+-----+           +-----+     +--------+     +------------+
                  |                      
<-----------------+               
ACME verifications
```

# backends

## certificate

Currently two backends are implemented:
* memory: certificates are stored in memory
* file: certificates are stored in a directory

## object

Currently two backend are implemented
* memory: objectes are stored in memory
* xorm: memory are stored in database

## nonce

Currently only memory is supported.

# TODOs

* implement tests
* additoonal backend for nonce (redis)
* additional backend for certiciates (s3)
* cron to cleanup database objects: authorization and challenges
* queuing for verifications