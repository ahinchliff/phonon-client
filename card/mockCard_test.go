package card

import (
	"testing"

	"github.com/GridPlus/phonon-client/cert"
	"github.com/GridPlus/phonon-client/model"
)

func TestCardPair(t *testing.T) {
	senderCard, err := NewMockCard(false, false)
	if err != nil {
		t.Error(err)
	}

	err = senderCard.InstallCertificate(cert.SignWithDemoKey)
	if err != nil {
		t.Error(err)
	}

	receiverCard, err := NewMockCard(false, false)
	if err != nil {
		t.Error(err)
	}
	err = receiverCard.InstallCertificate(cert.SignWithDemoKey)
	if err != nil {
		t.Error(err)
	}

	initPairingData, err := senderCard.InitCardPairing(receiverCard.IdentityCert)
	if err != nil {
		t.Error("error in initCardPairing")
		t.Error(err)
	}
	_, err = receiverCard.CardPair(initPairingData)
	if err != nil {
		t.Error("error in card pair")
		t.Error(err)
	}
}

func TestPostedPhononFlow(t *testing.T) {
	senderCard, err := NewMockCard(true, false)
	if err != nil {
		t.Error(err)
		return
	}

	recipientCard, err := NewMockCard(true, false)
	if err != nil {
		t.Error(err)
		return
	}

	senderCard.VerifyPIN("111111")
	recipientCard.VerifyPIN("111111")

	_, createdPhononPubKey, err := senderCard.CreatePhonon(model.Secp256k1)

	if err != nil {
		t.Error(err)
		return
	}

	transaction, err := senderCard.PostPhonons(recipientCard.IdentityPubKey, 1, []model.PhononKeyIndex{0})

	if err != nil {
		t.Error(err)
		return
	}

	err = recipientCard.ReceivePostedPhonons(transaction)

	if err != nil {
		t.Error(err)
		return
	}

	receivedPhononPubKey, err := recipientCard.GetPhononPubKey(0, model.Secp256k1)
	if err != nil {
		t.Error(err)
		return
	}

	if !createdPhononPubKey.Equal(receivedPhononPubKey) {
		t.Error("Created and received phonon pub keys do not match", createdPhononPubKey, receivedPhononPubKey)
		return
	}

}
