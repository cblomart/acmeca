package acme

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	//ginlogrus "github.com/toorop/gin-logrus"

	"github.com/cblomart/ACMECA/acme/ep"
	"github.com/cblomart/ACMECA/acme/ep/account"
	"github.com/cblomart/ACMECA/acme/ep/authz"
	"github.com/cblomart/ACMECA/acme/ep/cert"
	"github.com/cblomart/ACMECA/acme/ep/challenge"
	"github.com/cblomart/ACMECA/acme/ep/csr"
	"github.com/cblomart/ACMECA/acme/ep/directory"
	"github.com/cblomart/ACMECA/acme/ep/health"
	"github.com/cblomart/ACMECA/acme/ep/nonce"
	"github.com/cblomart/ACMECA/acme/ep/order"
	"github.com/cblomart/ACMECA/acme/validator"
	"github.com/cblomart/ACMECA/certstore"
	"github.com/cblomart/ACMECA/middlewares/ca"
	certstoremid "github.com/cblomart/ACMECA/middlewares/certstore"
	"github.com/cblomart/ACMECA/middlewares/decodejws"
	ginlog "github.com/cblomart/ACMECA/middlewares/log"
	"github.com/cblomart/ACMECA/middlewares/nocache"
	noncestoremid "github.com/cblomart/ACMECA/middlewares/noncestore"
	objstoremid "github.com/cblomart/ACMECA/middlewares/objectstore"
	"github.com/cblomart/ACMECA/middlewares/tokenauth"
	"github.com/cblomart/ACMECA/noncestore"
	"github.com/cblomart/ACMECA/objectstore"
)

func checkFile(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

// Server starts ACME server
func Server(v *cli.Context) error {
	// check modes
	modeAcme := v.Bool("acme")
	modeCA := v.Bool("ca")
	log.Infof("modes: acme=%t ca=%t", modeAcme, modeCA)
	if v.String("objectstorage") == "memory" && modeAcme {
		log.Warn("when using memory storage CA must be enabled")
		modeCA = true
	}
	// check that ca certificate exists
	if modeCA && (!checkFile(v.String("cacert")) || !checkFile(v.String("cakey"))) {
		log.Info("Generating CA certificate")
		generatetls(v.String("cacert"), v.String("cakey"), "", "", "", true)
	}
	if v.Bool("tls") {
		// check that certificates exists or create them
		if !checkFile(v.String("httpscert")) || !checkFile(v.String("httpskey")) {
			if !modeCA {
				// request certs from ca
				log.Infof("Requesting certificate from ca %s", v.String("caurl"))
				requesttls(v.String("httpscert"), v.String("httpskey"), v.String("hostnames"), v.String("caurl"), v.String("secret"))
			} else {
				log.Info("Generating HTTPS certificate")
				generatetls(v.String("httpscert"), v.String("httpskey"), v.String("hostnames"), v.String("cacert"), v.String("cakey"), false)
			}
		}
	}
	// allowing domains
	validator.AllowedDomains = v.String("domains")
	log.Infof("allowed domains: %s", validator.AllowedDomains)
	r := gin.New()
	r.Use(ginlog.Log(), gin.Recovery(), location.Default(), nocache.NoCache())
	// acme functions
	if modeAcme {
		ns, err := noncestore.Factory(v.String("noncestorage"), nil)
		if err != nil {
			return fmt.Errorf("Cannot create requested nonce storage: %s", err)
		}
		os, err := objectstore.Factory(v.String("objectstorage"), GetOpts(v.String("objectstorageopts")))
		if err != nil {
			return fmt.Errorf("Cannot create requested object storage: %s", err)
		}
		log.Infof("using '%s' nonce storage", v.String("noncestorage"))
		if os.Type() == "memory" {
			log.Warnf("using '%s' object storage", v.String("objectstorage"))
		} else {
			log.Infof("using '%s' object storage", v.String("objectstorage"))
		}
		if len(v.String("secret")) == 0 {
			log.Warn("secret is not initialized, please provide a secret yourself")
			key := make([]byte, 32)
			_, err := rand.Read(key)
			if err != nil {
				return fmt.Errorf("could not generate random secret")
			}
			secret := base64.RawURLEncoding.EncodeToString(key)
			log.Warnf("generated secret: %s", secret)
			v.Set("secret", secret)
		}
		caInfo := ca.Info(v.String("caurl"), v.String("secret"))
		base := r.Group("/")
		base.Use(noncestoremid.Store(ns), objstoremid.Store(os), decodejws.DecodeJWS())
		{
			base.GET(ep.HealthPath, caInfo, health.Get)
			base.HEAD(ep.HealthPath, caInfo, health.Get)
			base.GET(ep.DirectoryPath, directory.Get)
			base.GET(ep.NoncePath, nonce.Head)
			base.HEAD(ep.NoncePath, nonce.Head)
			base.POST(ep.AccountPath, account.Post)
			base.POST(ep.AccountPath+"/:id", account.Post)
			base.POST(ep.OrderPath, order.Post)
			base.POST(ep.OrderPath+"/:id", order.Post)
			base.POST(ep.AuthzPath+"/:id", authz.Post)
			base.POST(ep.ChallengePath+"/:id", challenge.Post)
			base.POST(ep.CsrPath+"/:id", caInfo, csr.Post)
			base.GET(ep.CertPath+"/:id", caInfo, cert.ProxyGet)
			base.POST(ep.CertPath+"/:id", caInfo, cert.ProxyGet)
		}
	}
	// ca functions
	if modeCA {
		// init ca signing middleware
		// get ca cert
		if !checkFile(v.String("cacert")) || !checkFile(v.String("cakey")) {
			return fmt.Errorf("couldn't find CA cert and key")
		}
		// read certificate
		crt, err := readCert(v.String("cacert"))
		if err != nil {
			return err
		}
		// read parent key
		key, err := readKey(v.String("cakey"))
		if err != nil {
			return err
		}
		// certiface store
		cs, err := certstore.Factory(v.String("certstorage"), crt, GetOpts(v.String("certstorageopts")))
		if err != nil {
			return fmt.Errorf("Cannot create requested cerft storage: %s", err)
		}
		if v.String("certstorage") == "memory" {
			log.Warnf("using '%s' cert storage", v.String("certstorage"))
		} else {
			log.Infof("using '%s' cert storage", v.String("certstorage"))
		}
		caGroup := r.Group("/ca")
		caGroup.Use(ca.Info(v.String("caurl"), v.String("secret")), certstoremid.Store(cs))
		{
			caGroup.GET(ep.HealthPath, health.CAGet)
			caGroup.HEAD(ep.HealthPath, health.CAGet)
			caGroup.GET(ep.CertPath+"/:id", cert.Get)
			caGroup.DELETE(ep.CertPath+"/:id", tokenauth.TokenAuth(), cert.Delete)
			caGroup.POST(ep.CsrPath, tokenauth.TokenAuth(), ca.Signing(key), csr.CaPost)
		}
	}
	if v.Bool("tls") {
		return r.RunTLS(v.String("listen"), v.String("httpscert"), v.String("httpskey"))
	}
	return r.Run(v.String("listen"))
}
