package repl

import (
  "math/big"
	"strconv"
  "github.com/GridPlus/phonon-client/tlv"
  "github.com/GridPlus/phonon-client/model"

  log "github.com/sirupsen/logrus"
	ishell "github.com/abiosoft/ishell/v2"
)

func createBrandedPhonon(c *ishell.Context, currencyType model.CurrencyType) {
  log.Debug("creating branded phonon")

  if ready := checkActiveCard(c); !ready {
		return
	}

  c.Println("What is source private key hex for this branded phonon?")
  // Example for Testing:
  // 03a0b699905d81fed15c814725f0e09bd275921f4b0657b364e4a80183eb0ebb
  sourcePrivKeyInput := c.ReadLine()

  extendedTLV := tlv.TLVList{}
  sourceTLV, err := model.TagFlexSourcePublicKey(sourcePrivKeyInput)
  if err != nil {
    c.Println("could not create tlv for source private key", err)
    return
  }
  extendedTLV = append(extendedTLV, sourceTLV)

  c.Println("What is the value of this branded phonon?")
  valueInput := c.ReadLine()

  value, err := strconv.ParseUint(valueInput, 10, 0)
  if err != nil {
    c.Println("value could not be parse: ", err)
    return
  }
  denomination, err := model.NewDenomination(big.NewInt(int64(value)))

  activeCard.CreatePhononSpecial(currencyType, denomination, extendedTLV)

}
