package order

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cblomart/ACMECA/acme/ep"
	"github.com/cblomart/ACMECA/acme/problem"
	"github.com/cblomart/ACMECA/middlewares/objectstore"
	"github.com/cblomart/ACMECA/objectstore/objects"
	"github.com/cblomart/ACMECA/objectstore/utils"
	"github.com/gin-contrib/location"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

const (
	// DefaultDurationMinutes is the time, in minutes, an order is valid
	DefaultDurationMinutes = 5
)

// Post handles a post request to order enpoint
func Post(c *gin.Context) {
	// get the use key id
	var kid string
	if tmp, ok := c.Get("kid"); ok {
		kid = fmt.Sprintf("%s", tmp)
	}
	// call to order must be identified
	if len(kid) == 0 {
		log.Errorf("recieved an order from an unidentified user")
		problem.Unauthorized(c)
		return
	}
	url := location.Get(c).String()
	store, err := objectstore.Get(c)
	if err != nil {
		log.Errorf("cannot rretrieve store: %s", err)
		problem.ServerInternal(c)
		return
	}
	// check the id of the request
	id := strings.Trim(c.Param("id"), "/")
	if len(id) > 0 {
		// post as get
		order, err := store.GetOrder(id)
		if err != nil {
			log.Errorf("cannot retrieve order: %s", err)
			problem.ServerInternal(c)
			return
		}
		if order != nil {
			// send the response
			log.Infof("returning order from id")
			log.Infof("oreder %s", order.String())
			c.Header("Link", fmt.Sprintf("<%s%s>;rel=\"index\"", url, ep.DirectoryPath))
			c.JSON(http.StatusOK, order)
			return
		}
		orders, err := store.GetOrderByAccount(id)
		if err != nil {
			log.Errorf("cannot retrieve store: %s", err)
			problem.ServerInternal(c)
			return
		}
		if orders != nil {
			// send the response
			log.Infof("returning order from account")
			c.Header("Link", fmt.Sprintf("<%s%s>;rel=\"index\"", url, ep.DirectoryPath))
			c.JSON(http.StatusOK, orders)
			return
		}
		log.Info("no order found for user or order %s", id)
		c.Status(http.StatusNotFound)
		return
	}
	// create a new order
	var payload string
	if tmp, ok := c.Get("payload"); ok {
		payload = fmt.Sprintf("%s", tmp)
	}
	if len(payload) == 0 {
		log.Errorf("recieved an empty order request")
		problem.Malformed(c)
		return
	}
	order := &objects.Order{}
	err = json.Unmarshal([]byte(payload), order)
	if err != nil {
		log.Errorf("cannot unmarshal order")
		problem.Malformed(c)
		return
	}
	order.ID = utils.ID()
	order.KeyID = kid
	log.Infof("recieved order %s from %s: %s", order.ID, order.KeyID, payload)
	// set basic properties
	order.Status = "pending"
	expires := time.Now().Add(time.Minute * DefaultDurationMinutes)
	order.Expires = &expires
	rejected, unsupported, err := store.CreateOrder(order, fmt.Sprintf("%s%s", url, ep.AuthzPath), fmt.Sprintf("%s%s", url, ep.ChallengePath), fmt.Sprintf("%s%s", url, ep.CsrPath))
	if unsupported != nil {
		problem.UnsupportedIdentifier(c)
		return
	}
	if rejected != nil {
		problem.RejectedIdentifier(c)
		return
	}
	if err != nil {
		problem.ServerInternal(c)
		return
	}
	jsonorder, _ := json.Marshal(order)
	log.Infof("created order: %s", jsonorder)
	//set headers
	c.Header("Link", fmt.Sprintf("<%s%s>;rel=\"index\"", url, ep.DirectoryPath))
	c.Header("Location", fmt.Sprintf("%s%s/%s", url, ep.OrderPath, order.ID))
	c.JSON(http.StatusCreated, order)
	return
}
