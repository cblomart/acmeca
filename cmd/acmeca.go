package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/cblomart/ACMECA/acme"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "server",
		Usage: "Start ACME server",
		Action: func(c *cli.Context) error {
			return acme.Server(c)
		},
		Flags: []cli.Flag{
			// use http or https
			&cli.BoolFlag{
				Name:    "tls",
				Value:   true,
				Usage:   "listen to https",
				EnvVars: []string{"TLS"},
			},
			// HTTPS certificate will either be requested to ca or generetaed from CA
			&cli.StringFlag{
				Name:    "httpscert",
				Value:   "/etc/acmeca/certs/https.crt",
				Usage:   "Certificate to use for HTTPS",
				EnvVars: []string{"HTTPS_CERT"},
			},
			&cli.StringFlag{
				Name:    "httpskey",
				Value:   "/etc/acmeca/certs/https.pem",
				Usage:   "Key to use for HTTPS",
				EnvVars: []string{"HTTPS_KEY"},
			},
			&cli.StringFlag{
				Name:    "hostnames",
				Value:   "localhost",
				Usage:   "Hostname for self sign certificate",
				EnvVars: []string{"HOSTNAMES"},
			},
			&cli.StringFlag{
				Name:    "listen",
				Value:   ":8443",
				Usage:   "Address to listen to",
				EnvVars: []string{"LISTEN"},
			},
			&cli.StringFlag{
				Name:    "noncestorage",
				Value:   "memory",
				Usage:   "Nonce storage type to use",
				EnvVars: []string{"NONCE_STORAGE"},
			},
			&cli.StringFlag{
				Name:    "objectstorage",
				Value:   "xorm",
				Usage:   "Object storage type to use",
				EnvVars: []string{"OBJECT_STORAGE"},
			},
			&cli.StringFlag{
				Name:    "objectstorageopts",
				Value:   "",
				Usage:   "Object storage options (key1=value1;key2=value2;...)",
				EnvVars: []string{"OBJECT_STORAGE_OPTS"},
			},
			&cli.StringFlag{
				Name:    "certstorage",
				Value:   "file",
				Usage:   "certificate storage type to use",
				EnvVars: []string{"CERT_STORAGE"},
			},
			&cli.StringFlag{
				Name:    "certstorageopts",
				Value:   "",
				Usage:   "certificate storage options (key1=value1;key2=value2...)",
				EnvVars: []string{"CERT_STORAGE_OPTS"},
			},
			&cli.StringFlag{
				Name:    "domains",
				Value:   ".local",
				Usage:   "allowed top level domains",
				EnvVars: []string{"DOMAINS"},
			},
			&cli.BoolFlag{
				Name:    "ca",
				Value:   false,
				Usage:   "enable ca requests",
				EnvVars: []string{"CA"},
			},
			&cli.StringFlag{
				Name:    "cacert",
				Value:   "/etc/acmeca/certs/ca.crt",
				Usage:   "CA certificate",
				EnvVars: []string{"CACERT"},
			},
			&cli.StringFlag{
				Name:    "cakey",
				Value:   "/etc/acmeca/certs/ca.pem",
				Usage:   "CA key",
				EnvVars: []string{"CAKEY"},
			},
			&cli.BoolFlag{
				Name:    "acme",
				Value:   true,
				Usage:   "enable acme requests",
				EnvVars: []string{"ACME"},
			},
			&cli.StringFlag{
				Name:     "secret",
				Value:    "",
				Usage:    "secret for communication with ca (picked from /run/secrets/acmesecret)",
				EnvVars:  []string{"SECRET"},
				FilePath: "/run/secrets/acmesecret",
			},
			&cli.StringFlag{
				Name:    "caurl",
				Value:   "https://localhost:8443/ca",
				Usage:   "url to ca",
				EnvVars: []string{"CASERVER"},
			},
			&cli.BoolFlag{
				Name:    "cron",
				Value:   true,
				Usage:   "cron tasks",
				EnvVars: []string{"ACMECRON"},
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
