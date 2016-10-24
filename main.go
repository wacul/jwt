package main

import (
	"log"

	flags "github.com/jessevdk/go-flags"
	"github.com/wacul/jwt/encode"
)

// Options is the root of commandline-arguments struction
type Options struct {
	Encode encode.Encode `command:"encode" description:"Encode header/payload to JSON Web Token"`
}

func main() {
	_, err := flags.Parse(&Options{})
	if err != nil {
		log.Fatal(err)
	}
}
