// Command hidden_relay_go is a command line tool for hidden/virtual relay
// addresses.
//
//	hidden_relay_go nrv-decode <nrvrelay1... | nostr+nrv://...>
//	hidden_relay_go nrv-encode <hex-pubkey> [relay ...]
package main

import (
	"fmt"
	"os"
	"path/filepath"

	nrv "github.com/paulle0/hidden_relay_go/nrvaddress"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", programName(), err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage(os.Stderr)
		return fmt.Errorf("no command given")
	}

	switch command := args[0]; command {
	case "nrv-decode":
		return decodeCommand(args[1:])
	case "nrv-encode":
		return encodeCommand(args[1:])
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	default:
		usage(os.Stderr)
		return fmt.Errorf("unknown command %q", command)
	}
}

// decodeCommand prints the public key and rendezvous relays of an address in
// either the bech32 or the url representation.
func decodeCommand(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: %s nrv-decode <nrvrelay1... | nostr+nrv://...>", programName())
	}

	address, err := nrv.Decode(args[0])
	if err != nil {
		return err
	}

	fmt.Printf("pubkey: %s\n", address.PublicKey)
	if len(address.Relays) == 0 {
		fmt.Println("relays: (none)")
		return nil
	}
	fmt.Println("relays:")
	for _, relay := range address.Relays {
		fmt.Printf("  %s\n", relay)
	}
	return nil
}

// encodeCommand prints both representations of the address built from a public
// key and its rendezvous relays.
func encodeCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: %s nrv-encode <hex-pubkey> [relay ...]", programName())
	}

	address := nrv.Address{PublicKey: args[0], Relays: args[1:]}
	bech32Address, urlAddress, err := nrv.Encode(address)
	if err != nil {
		return err
	}

	fmt.Println(bech32Address)
	fmt.Println(urlAddress)
	return nil
}

func usage(w *os.File) {
	name := programName()
	fmt.Fprintf(w, `Usage:
  %[1]s nrv-decode <nrvrelay1... | nostr+nrv://...>
        print the hex public key and the rendezvous relays of an address

  %[1]s nrv-encode <hex-pubkey> [relay ...]
        print the nrvrelay1... and nostr+nrv://... forms of an address
`, name)
}

func programName() string {
	if len(os.Args) == 0 {
		return "hidden_relay_go"
	}
	return filepath.Base(os.Args[0])
}
