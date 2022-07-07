package repl

import (
  "strconv"
  log "github.com/sirupsen/logrus"
	ishell "github.com/abiosoft/ishell/v2"
)

func flexPhonons(c *ishell.Context) {
  log.Debug("initiating flexPhonons")

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

  err = activeCard.SendFlexPhonon(uint16(keyIndexSend), uint64(value))
  if err != nil {
    c.Println("error during flex phonons: ", err)
    return
  }
}
