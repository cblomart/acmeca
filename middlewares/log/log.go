package log

import (
	"fmt"
	"runtime"
	"time"

	"github.com/cblomart/ACMECA/objectstore/utils"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Log provides logging for gin
func Log() gin.HandlerFunc {
	return func(c *gin.Context) {
		starttime := time.Now()
		reqid := utils.ID()
		fields := log.Fields{
			"reqid":      reqid,
			"method":     c.Request.Method,
			"URI":        c.Request.RequestURI,
			"clientip":   c.Request.RemoteAddr,
			"keyid":      "-",
			"instanceid": "-",
			"latency":    0,
			"status":     0,
			"length":     0,
		}
		iid := c.Param("id")
		if len(iid) > 0 {
			fields["instanceid"] = iid
		}
		log.WithFields(fields).Infof("request started")
		c.Next()
		if kid, ok := c.Get("kid"); ok {
			fields["keyid"] = fmt.Sprintf("%s", kid)
		}
		fields["status"] = c.Writer.Status()
		fields["length"] = c.Writer.Size()
		endtime := time.Now()
		latency := endtime.Sub(starttime)
		fields["latency"] = latency.Milliseconds()
		c.Header("latency", latency.String())
		c.Header("gover", runtime.Version())
		log.WithFields(fields).Infof("request finished")
	}
}
