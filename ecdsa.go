 package main

 import (
 	"crypto/ecdsa"
 	"crypto/elliptic"
 	"crypto/sha256"
 	"crypto/rand"
 	"fmt"
 	"hash"
 	"io"
 	"math/big"
 	"os"
 )

 func main() {

 	curve := elliptic.P256() //source is http://golang.org/pkg/crypto/elliptic/#P256

 	privatekey := new(ecdsa.PrivateKey)
	 privatekey, err := ecdsa.GenerateKey(curve, rand.Reader) //generate a private key from curve which 
	                                                          // is then used to obtain the public key

 	if err != nil {
 		fmt.Println(err)
 		os.Exit(1)
 	}

 	var publickey ecdsa.PublicKey
 	publickey = privatekey.PublicKey

 	fmt.Println("Private Key :")
 	fmt.Printf("%x \n", privatekey)

 	fmt.Println("Public Key :")
 	fmt.Printf("%x \n", publickey)

 	//Signing the message with a sha 256 hash

 	var h hash.Hash
 	h = sha256.New()
 	r := big.NewInt(0)
 	s := big.NewInt(0)

 	io.WriteString(h, "Random message to be signed")
 	signhash := h.Sum(nil) //hashing the message

	 r, s, signerr := ecdsa.Sign(rand.Reader, privatekey, signhash) //using the signatures hash the rand used
	                                                                // to obtain priv key and the key as well
 	if signerr != nil {
 		fmt.Println(err)
 		os.Exit(1)
 	}

 	signature := r.Bytes()
 	signature = append(signature, s.Bytes()...) // add/append s to existing r

 	fmt.Printf("Signature : %x\n", signature)

 	// Verify
	 hashverify := ecdsa.Verify(&publickey, signhash, r, s) // verify the hash of the signature with public key
	                                                          // and bytes of the sign
 	fmt.Println(hashverify) // true if not tampered by any attacks
 }