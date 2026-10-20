package main

import (
	"flag"
	"fmt"
	"os"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

func main() {
	role := flag.String("role", "", "the database role the host signs in to the identity project as; required")
	flag.Parse()
	sql, err := mwanachamaauth.IdentitySessionFunctions(*role)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Print(sql)
}
