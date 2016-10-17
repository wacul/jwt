package main

import (
	"fmt"
	"os"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
	jwt "gopkg.in/dgrijalva/jwt-go.v2"
)

func main() {
	app := kingpin.New("jwt", "JSON Web Token (JWT) encoder/decoder CLI tool")

	encoder := app.Command("encode", "Encode header/payload to JSON Web Token")
	header := map[string]string{}
	payload := map[string]string{}
	encoder.Flag("header", "Headers pair(key=value) for a token").Short('h').StringMapVar(&header)
	encoder.Flag("payload", "Payloads pair(key=value) for a token").Short('p').StringMapVar(&payload)
	var secret string
	secretFlag := encoder.Flag("secret", "A secret key for verify signature").Short('s')
	secretFlag.StringVar(&secret)

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case encoder.FullCommand():
		token := jwt.New(jwt.GetSigningMethod("HS256"))
		for key, value := range header {
			token.Header[key] = value
		}
		for key, value := range payload {
			token.Claims[key] = value
		}

		if secret != "" {
			gen, err := token.SignedString([]byte(secret))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to generate signed JWT with "+err.Error())
				os.Exit(1)
			}
			fmt.Println(gen)
		} else {
			gen, err := token.SigningString()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to generate signed JWT with "+err.Error())
				os.Exit(1)
			}
			fmt.Println(gen)
		}
	}

	// decoder := app.Command("decode", "Decode header/payload to JSON Web Token")
	// encoder := app.Command("encode-file", "Encode header/payload to JSON Web Token").Alias("ef")
	// decoder := app.Command("decode", "Decode header/payload to JSON Web Token").Alias("decoder")
	// decoder.Arg("token", "Tokens ").StringsVar()
	//

}
