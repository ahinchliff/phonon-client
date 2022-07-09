package repl

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/GridPlus/phonon-client/util"
	ishell "github.com/abiosoft/ishell/v2"
	log "github.com/sirupsen/logrus"
)

func postPhonons(c *ishell.Context) {
	log.Debug("initiating postPhonons")
	if ready := checkActiveCard(c); !ready {
		return
	}

	c.Println("What is receiving card's public key hex?")
	receivingPubKeyInput := c.ReadLine()
	receivingCardPubKeybytes, err := hex.DecodeString(receivingPubKeyInput)
	receivingCardPubKey, err := util.ParseECCPubKey(receivingCardPubKeybytes)
	if err != nil {
		c.Println("could not decode public key hex: ", err)
		return
	}

	c.Println("What is receiving card's receipt nonce?")
	nonceInput := c.ReadLine()
	nonce, err := strconv.ParseUint(nonceInput, 10, 64)
	if err != nil {
		c.Println("could not parse nonce: ", err)
		return
	}

	// Need to consume array not single phonon
	c.Println(`Which phonon(s) do you want to post?
         Args: [KeyIndex] space dilineated for multiple phonons`)
	phononInput := c.ReadLine()
	phononInputParts := strings.Split(phononInput, " ")

	var keyIndices []uint16
	for i := 0; i < len(phononInputParts); i++ {
		keyindex, err := strconv.ParseUint(phononInputParts[i], 10, 16)
		if err != nil {
			c.Println("error parsing arg: ", i)
			c.Println("aborting send operation...")
			return
		}
		keyIndices = append(keyIndices, uint16(keyindex))
	}

	transferPhononPackets, err := activeCard.PostPhonons(receivingCardPubKey, nonce, keyIndices)
	if err != nil {
		c.Println("error during post phonons: ", err)
		return
	}

	transferPhononPacketsString := hex.EncodeToString(transferPhononPackets)
	c.Println("returned posted phonon packet hex:", transferPhononPacketsString)
}

func receivePostedPhonons(c *ishell.Context) {
	log.Debug("initiating receivePostedPhonons")

	if ready := checkActiveCard(c); !ready {
		return
	}

	c.Println("What is the posted bytes packet hex?")
	postedPacketInput := c.ReadLine()
	postedPacket, err := hex.DecodeString(postedPacketInput)
	if err != nil {
		c.Println("could not decode posted packet", err)
		return
	}

	err = activeCard.ReceivePostedPhonons(postedPacket)
	if err != nil {
		c.Println("error during post phonons: ", err)
		return
	}

}

func identifyCard(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}

	nonce := make([]byte, 32)
	cardPubKey, _, err := activeCard.IdentifyCard(nonce)
	if err != nil {
		c.Println("error during post phonons: ", err)
		return
	}

	c.Println("pub key hex string:")
	c.Println(util.ECCPubKeyToHexString(cardPubKey))
	return
}

func identifyPostedPhononNonce(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}

	nonce, err := activeCard.IdentifyPostedPhononNonce()
	if err != nil {
		c.Println("error getting posted phonon nonce: ", err)
		return
	}
	c.Println("Current posted phonon nonce: ", nonce)
	c.Println("Next avaialble posted phonon nonce: ", nonce+1)
}
