package encode

import (
	"fmt"
	"strings"

	"github.com/SermoDigital/jose"
	"github.com/SermoDigital/jose/jws"
)

// Encode headers and claims to JWS/JWT
type Encode struct {
	Header        map[string]string `long:"header" description:"Headers pair(key=value) for a token"`
	Claims        map[string]string `long:"claims" description:"Claims pair(key=value) for a token"`
	SigningMethod string            `long:"signing-method"description:"A signing method for verify signature" choice:"none" choice:"HS256" choice:"RS256" default:"none"`
	Secret        string            `long:"secret" description:"A secret key for verify signature"`
}

// Execute encodes to JWS/JWT with parsed arguments
func (e *Encode) Execute(args []string) error {

	claims := jws.Claims{}
	for key, value := range e.Claims {
		claims.Set(key, value)
	}

	if e.SigningMethod == "none" {
		terms := make([]string, 0, 3)
		header := jose.Protected{}
		for key, value := range e.Header {
			header.Set(key, value)
		}
		header64, err := header.Base64()
		if err != nil {
			return err
		}
		if len(header64) > 0 {
			terms = append(terms, string(header64))
		}
		claims64, err := claims.Base64()
		if err != nil {
			return err
		}
		if len(claims64) > 0 {
			terms = append(terms, string(claims64))
		}
		if len(terms) > 0 {
			fmt.Println(strings.Join(terms, "."))
		}
	} else {
		method := jws.GetSigningMethod(e.SigningMethod)
		if method == nil {
			return fmt.Errorf("specified signing method '%s' is not registered", e.SigningMethod)
		}

		jot := jws.New(claims, method)
		for key, value := range e.Header {
			jot.Protected().Set(key, value)
		}
		token, err := jot.Compact([]byte(e.Secret))
		if err != nil {
			return err
		}
		fmt.Println(string(token))
	}
	return nil
}
