package card

import (
	"github.com/GridPlus/keycard-go"
	"github.com/GridPlus/keycard-go/globalplatform"
	"github.com/GridPlus/keycard-go/gridplus"
	"github.com/GridPlus/keycard-go/types"
	log "github.com/sirupsen/logrus"
)

var phononAID = []byte{0xA0, 0x00, 0x00, 0x08, 0x20, 0x00, 0x03, 0x01}

type PhononCommandSet struct {
	c               types.Channel
	sc              *keycard.SecureChannel
	ApplicationInfo *types.ApplicationInfo //TODO: Determine if needed
	PairingInfo     *types.PairingInfo
}

func NewPhononCommandSet(c types.Channel) *PhononCommandSet {
	return &PhononCommandSet{
		c:               c,
		sc:              keycard.NewSecureChannel(c),
		ApplicationInfo: &types.ApplicationInfo{},
	}
}

func (cs *PhononCommandSet) Select() error {
	cmd := globalplatform.NewCommandSelect(phononAID)
	resp, err := cs.c.Send(cmd)
	if err != nil {
		log.Error("could not send select command. err: ", err)
		return err
	}
	_, cardPubKey, err := gridplus.ParseSelectResponse(resp.Data)
	if err != nil {
		return err
	}
	err = cs.sc.GenerateSecret(cardPubKey)
	if err != nil {
		return err
	}

	return nil
}