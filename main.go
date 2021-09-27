package main

import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/sha256"
    "encoding/pem"
    "fmt"
    "os"
)

func main() {
    // generate key
    privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        fmt.Printf("Cannot generate RSA key\n")
        os.Exit(1)
    }
    publickey := &privatekey.PublicKey
	fmt.Printf("privatekey %v,pubkey %v\n",privatekey,publickey)

	// dump private key to file
    var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
    privateKeyBlock := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: privateKeyBytes,
    }
    privatePem, err := os.Create("private.pem")
    if err != nil {
        fmt.Printf("error when create private.pem: %s \n", err)
        os.Exit(1)
    }
    err = pem.Encode(privatePem, privateKeyBlock)
    if err != nil {
        fmt.Printf("error when encode private pem: %s \n", err)
        os.Exit(1)
    }

    // dump public key to file
    publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
    if err != nil {
        fmt.Printf("error when dumping publickey: %s \n", err)
        os.Exit(1)
    }
    publicKeyBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }
    publicPem, err := os.Create("public.pem")
    if err != nil {
        fmt.Printf("error when create public.pem: %s \n", err)
        os.Exit(1)
    }
    err = pem.Encode(publicPem, publicKeyBlock)
    if err != nil {
        fmt.Printf("error when encode public pem: %s \n", err)
        os.Exit(1)
    }

	// encrypt msg
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publickey,
		[]byte("super secret message"),
		nil)
	if err != nil {
		panic(err)
	}

	fmt.Println("encrypted bytes: ", encryptedBytes)

	// decrypt 
	decryptedBytes, err := privatekey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}

	fmt.Println("decrypted message: ", string(decryptedBytes))


	// verify sign
	msg := []byte("verifiable message")

	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)
	// private key sign
	signature, err := rsa.SignPSS(rand.Reader, privatekey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("signature",string(signature))

	// publick key verify
	err = rsa.VerifyPSS(publickey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return
	}
	fmt.Println("signature verified")

}
