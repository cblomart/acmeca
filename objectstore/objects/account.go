package objects

// Account represents users accountsS
type Account struct {
	KeyID                string   `json:"-",xorm:"index"`
	Key                  string   `json:"-"`
	Status               string   `json:"status"`
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Orders               string   `json:"orders"`
}

// Check checks if an account is valid
func (a *Account) Check() bool {
	return len(a.KeyID) > 0 && len(a.Key) > 0
}

// Update updates an account
func (a *Account) Update(b Account) {
	if len(b.Contact) > 0 {
		a.Contact = b.Contact
	}
}
