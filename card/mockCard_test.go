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

func TestCreatePostedPhonons(t *testing.T) {
	senderCard, err := NewMockCard(true, false)
	if err != nil {
		t.Error(err)
	}

	recipientCard, err := NewMockCard(true, false)
	if err != nil {
		t.Error(err)
	}

	senderCard.VerifyPIN("111111")
	recipientCard.VerifyPIN("111111")

	keyIndex, pubKey, err := senderCard.CreatePhonon(model.Secp256k1)

	if err != nil {
		t.Error(err)
	}

	if keyIndex != 0 {
		t.Error("keyIndex is not 0;", keyIndex)
	}

	if pubKey == nil {
		t.Error("pubKey is nil", pubKey)
	}

	// todo - work out correct way to pass in recipients public key
	transaction, err := senderCard.SendPostedPhonons(recipientCard.IdentityPubKey.X.Bytes(), 1, []uint16{0})

	if err != nil {
		t.Error(err)
	}

	err = recipientCard.ReceivePostedPhonons(transaction)

	if err != nil {
		t.Error(err)
	}

}
