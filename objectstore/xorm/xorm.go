package xorm

import (
	"fmt"

	"github.com/cblomart/ACMECA/objectstore/objects"
	_ "github.com/denisenkom/go-mssqldb" // xorm support for mssql
	_ "github.com/go-sql-driver/mysql"   // xorm support for mysql
	_ "github.com/lib/pq"                // xorm support for postgress
	_ "github.com/mattn/go-sqlite3"      // xorm support for sqlite

	log "github.com/sirupsen/logrus"
	"xorm.io/xorm"
)

// Store stores ACME objects in memory
type Store struct {
	engine *xorm.Engine
}

// Type returns the storage type
func (s *Store) Type() string {
	return "xorm"
}

// Init initializes the xorm object store
func (s *Store) Init(opts map[string]string) error {
	drivername := "sqlite3"
	dataSourceName := "/var/acmeca/acmeca.db"
	if drv, ok := opts["driver"]; ok {
		drivername = drv
		log.Infof("using driver from opts: %s", drivername)
	}
	if source, ok := opts["source"]; ok {
		dataSourceName = source
		log.Infof("using source from opts: %s", dataSourceName)
	}
	engine, err := xorm.NewEngine(drivername, dataSourceName)
	if err != nil {
		return fmt.Errorf("could initiate xorm engine: %s", err)
	}
	s.engine = engine
	err = s.engine.Sync2(new(objects.Account), new(objects.Identifier), new(objects.Order), new(objects.Authorization), new(objects.Challenge), new(OrdersToIdentifiers))
	if err != nil {
		return fmt.Errorf("failed to sync to db: %s", err)
	}
	return nil
}
