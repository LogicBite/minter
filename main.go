package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/sha3"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// AssetRes is the response from the assets/{hash} endpoint
type AssetRes struct {
	Data     Asset
	Position Position
}

func main() {
	generateKeys := flag.Bool("keypair", false, "Generates and displays new private and public keys --keypair")
	keyStr := flag.String("key", "", "Sets the private key --key 2c3cc26268eaaca1be7b1bf88c0fcf0a1e07e9065c01add4aad228a1a030ed06d3941323359272d3516d92468d4ce65df9b54bdbcbe90d2e7b93aa4c9145d599")
	mint := flag.Bool("mint", false, "Indicate that you are minting an nft for the first time --mint")
	sendAddress := flag.String("send", "", "Sends a non fungible token to the given public address --send 457369b27f82f4d5f50f8d2b6caf6c2143fc8c378c1d4c7f46aed17447705bbb")
	sendPath := flag.String("path", "", "Path to the data containing the data to to tokenize --path /home/file.txt")

	flag.Parse()

	if *generateKeys {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		check(err)
		fmt.Println("Public Key\n" + hex.EncodeToString(pubKey))
		fmt.Println("\nPrivate Key\n" + hex.EncodeToString(privKey))
		os.Exit(1)
	}

	if *sendPath == "" {
		fmt.Println("Filepath is required.")
		os.Exit(1)
	}

	dat, err := ioutil.ReadFile(*sendPath)
	check(err)

	privKey := ed25519.PrivateKey{}
	pubKey := ed25519.PublicKey{}

	if *keyStr == "" {
		fmt.Println("Key is required.")
		os.Exit(1)
	} else {
		privKey, err = hex.DecodeString(*keyStr)
		pubKey = privKey.Public().(ed25519.PublicKey)
	}

	payload := Asset{}

	if *mint {
		payload = Asset{
			PrevTx:  Position{},
			Hash:    sha3.Sum256(dat),
			Owner:   pubKey,
			Creator: pubKey,
		}
	} else {
		hash := sha3.Sum256(dat)

		resp, err := http.Get("http://localhost:13131/tokens/" + hex.EncodeToString(hash[:]))
		check(err)
		body, err := ioutil.ReadAll(resp.Body)

		res := AssetRes{}
		msgpack.Unmarshal(body, &res)

		empty := [32]byte{}
		if bytes.Equal(empty[:], res.Data.Hash[:]) {
			fmt.Println("No token found on the blockchain for this file. Use --mint to mint it.")
			os.Exit(1)
		}

		if *sendAddress == "" {
			fmt.Println("Send to address is required with --send.")
			os.Exit(1)
		}

		sendTo := ed25519.PublicKey{}
		sendTo, err = hex.DecodeString(*sendAddress)

		payload = Asset{
			Hash:    sha3.Sum256(dat),
			PrevTx:  Position{},
			Owner:   sendTo,
			Creator: pubKey,
		}
	}

	payload.sign(privKey)

	body, err := msgpack.Marshal(&payload)
	check(err)

	resp, err := http.Post("http://localhost:13131/tokens/mint", "application/msgpack", bytes.NewBuffer(body))
	check(err)
	if resp.StatusCode == 201 {
		status := ""
		if *mint {
			status = "minted"
		} else {
			status = "sent"
		}

		fmt.Println("Successfully " + status + " NFT. Hash: " + hex.EncodeToString(payload.Hash[:]))
	} else {
		status := ""
		if *mint {
			status = "minting"
		} else {
			status = "sending"
		}
		fmt.Println("There was an error when " + status + " the NFT. The transaction was rejected by the network.")
	}
}
