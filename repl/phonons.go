package repl

import (
	"crypto/sha256"
	"strconv"

	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/util"
	ishell "github.com/abiosoft/ishell/v2"
	"github.com/btcsuite/btcutil/base58"
)

func createPhonon(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}
	keyIndex, pubKey, err := activeCard.CreatePhonon()
	if err != nil {
		c.Println("error creating phonon: ", err)
		return
	}
	c.Println("created phonon")
	c.Println("Key Index: ", keyIndex)
	c.Println("Public Key: ", util.ECDSAPubKeyToHexString(pubKey))
}

func listPhonons(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}
	var currencyType model.CurrencyType = 0
	var lessThanValue float32 = 0
	var greaterThanValue float32 = 0
	var numCorrectArgs = 3

	if len(c.Args) == numCorrectArgs {
		currencyTypeInt, err := strconv.ParseInt(c.Args[0], 10, 0)
		if err != nil {
			c.Println("error parsing currencyType: ", err)
			return
		}
		currencyType = model.CurrencyType(currencyTypeInt)

		lessThanValueRaw, err := strconv.ParseFloat(c.Args[1], 32)
		if err != nil {
			c.Println("error parsing lessThanValue: ", err)
			return
		}
		lessThanValue = float32(lessThanValueRaw)

		greaterThanValueRaw, err := strconv.ParseFloat(c.Args[2], 32)
		if err != nil {
			c.Println("error parsing greaterThanValue: ", err)
			return
		}
		greaterThanValue = float32(greaterThanValueRaw)
	}
	phonons, err := activeCard.ListPhonons(currencyType, lessThanValue, greaterThanValue)
	if err != nil {
		c.Println("error listing phonons: ", err)
		return
	}
	for _, p := range phonons {
		p.PubKey, err = activeCard.GetPhononPubKey(p.KeyIndex)
		c.Println("retrieved pubKey: ", p.PubKey)
		if err != nil {
			c.Printf("error retrieving phonon pubKey at keyIndex %v. err: %v\n", p.KeyIndex, err)
		}
	}
	c.Println("phonons: ")
	for _, p := range phonons {
		c.Printf("%v\n", p)
	}
}

func setDescriptor(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}
	numCorrectArgs := 3
	if len(c.Args) != numCorrectArgs {
		c.Println("setDescriptor requires %v args", numCorrectArgs)
		return
	}

	keyIndex, err := strconv.ParseUint(c.Args[0], 10, 16)
	if err != nil {
		c.Println("keyIndex could not be parsed: ", err)
		return
	}
	//TODO: Present these options better
	currencyTypeInt, err := strconv.Atoi(c.Args[1])
	if err != nil {
		c.Println("currencyType could not be parse: ", err)
		return
	}
	currencyType := model.CurrencyType(currencyTypeInt)

	value, err := strconv.ParseFloat(c.Args[2], 32)
	if err != nil {
		c.Println("value could not be parse: ", err)
		return
	}
	c.Println("setting descriptor with values: ", uint16(keyIndex), currencyType, float32(value))
	err = activeCard.SetDescriptor(uint16(keyIndex), currencyType, float32(value))
	if err != nil {
		c.Println("could not set descriptor: ", err)
		return
	}
	c.Println("descriptor set successfully")
	//TODO: wizard?
	//TODO: Resolve SetDescriptor issue on card
}

func redeemPhonon(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}
	numCorrectArgs := 1
	if len(c.Args) != numCorrectArgs {
		c.Println("incorrect number of args")
		return
	}

	keyIndex, err := strconv.ParseUint(c.Args[0], 10, 16)
	if err != nil {
		c.Println("could not parse keyIndex arg: ", err)
		return
	}
	selection := c.MultiChoice([]string{"no", "yes"},
		"Are you sure you wish to redeem this phonon?\n"+
			"Performing this action will permanently delete the phonon from the card and present you "+
			`with it's private key. After this, preserving this private key is your responsibility `+
			`and there will be no other way to retrieve it.`)
	if selection == 0 {
		c.Println("phonon redemption canceled")
		return
	}
	privKey, err := activeCard.DestroyPhonon(uint16(keyIndex))
	if err != nil {
		c.Printf("unable to redeem and destroy phonon at keyIndex %v, err: %v\n", keyIndex, err)
	}
	c.Println("redeemed phonon at keyIndex: ", keyIndex)
	c.Println("private key: ")
	//TODO: Find a better encoding format
	c.Printf("%x\n", privKey.D)

	//temporary code for BTC export
	c.Println("WIF format for BTC keys:")
	wifBytes := append([]byte{0x80}, privKey.D.Bytes()...)
	tmp := sha256.Sum256(wifBytes)
	chksum := sha256.Sum256(tmp[:])
	wifBytes = append(wifBytes, chksum[0:4]...)
	base58WIF := base58.Encode(wifBytes)
	c.Println(base58WIF)

}
