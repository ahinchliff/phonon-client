package repl

import (
  "math/big"
  "strconv"
  "github.com/GridPlus/phonon-client/tlv"
  "github.com/GridPlus/phonon-client/model"

  log "github.com/sirupsen/logrus"
  ishell "github.com/abiosoft/ishell/v2"
)

func createFlexiblePhonon(c *ishell.Context, currencyType model.CurrencyType) {
  log.Debug("creating flexible phonon")

  if ready := checkActiveCard(c); !ready {
    return
  }

  c.Println("What is source private key hex for this flexible phonon?")
  // Example for Testing:
  // 03a0b699905d81fed15c814725f0e09bd275921f4b0657b364e4a80183eb0ebb
  sourcePrivKeyInput := c.ReadLine()

  // check priv key length (this is also checked on card)
  if (len(sourcePrivKeyInput) != 64) {
    c.Println("your private key must be 64 characters long")
    return
  }

  c.Println("What is the value of this flexible phonon?")
  valueInput := c.ReadLine()

  value, err := strconv.ParseUint(valueInput, 10, 0)
  if err != nil {
    c.Println("value could not be parse: ", err)
    return
  }
  denomination, err := model.NewDenomination(big.NewInt(int64(value)))

  extendedTLV := tlv.TLVList{}

  p := &model.Phonon{
    CurrencyType: currencyType,
    Denomination: denomination,
    ExtendedTLV: extendedTLV,
  }

  _, _, err = activeCard.CreatePhononWithSetDescriptor(p, sourcePrivKeyInput)
  if err != nil {
    c.Println("error creating flex phonon: ", err)
    return
  }
}

func sendFlex(c *ishell.Context) {
  log.Debug("initiating sendFlex")

  if ready := checkActiveCard(c); !ready {
		return
	}

  numCorrectArgs := 2
  if len(c.Args) != numCorrectArgs {
    c.Printf("flexPhonon requires %v args\n", numCorrectArgs)
    return
  }

  keyIndexSend, err := strconv.ParseUint(c.Args[0], 10, 16)
  if err != nil {
    c.Println("keyIndex for phonon to send could not parse: ", err)
    return
  }

  value, err := strconv.ParseUint(c.Args[1], 10, 64)
  if err != nil {
    c.Println("value could not be parse: ", err)
    return
  }

  err = activeCard.SendFlex(uint16(keyIndexSend), uint64(value))
  if err != nil {
    c.Println("error during flex phonons: ", err)
    return
  }
}

func consolidateFlex(c *ishell.Context) {
  numCorrectArgs := 2
	if len(c.Args) != numCorrectArgs {
		c.Printf("consolidateFlex requires %v args\n", numCorrectArgs)
		return
	}

	keyIndexKeep, err := strconv.ParseUint(c.Args[0], 10, 16)
	if err != nil {
		c.Println("keyIndex could not be parsed: ", err)
		return
	}

  keyIndexDestroy, err := strconv.ParseUint(c.Args[1], 10, 16)
	if err != nil {
		c.Println("keyIndex could not be parsed: ", err)
		return
	}

  err = activeCard.ConsolidateFlex(uint16(keyIndexKeep), uint16(keyIndexDestroy))
  if err != nil {
    c.Println("error during consolidate fleixible phonon: ", err)
    return
  }
}
