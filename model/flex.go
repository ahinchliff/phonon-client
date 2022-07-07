package model

import (
  "errors"
  "github.com/GridPlus/phonon-client/tlv"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	log "github.com/sirupsen/logrus"
)
const (
  SourcePublicKey = 0x58
)

// takes a hex private key and deduces its public key
func TagFlexSourcePublicKey(privateKey string) (sourcePublicKeyTLV tlv.TLV, err error) {

    // check length
    if (len(privateKey) != 64) {
      return tlv.TLV{}, errors.New("private key hex must be 64 characters long")
    }

    privateKeyParsed, err := ethcrypto.HexToECDSA(privateKey)
    if err != nil {
  		return tlv.TLV{},  err
  	}
    publicKeyBytes := ethcrypto.FromECDSAPub(&privateKeyParsed.PublicKey)
    log.Debug(publicKeyBytes) // public bytes

    sourcePublicKeyTLV, err = tlv.NewTLV(SourcePublicKey, publicKeyBytes)
    if err != nil {
  		return tlv.TLV{},  err
  	}
    log.Debug(sourcePublicKeyTLV)

    return sourcePublicKeyTLV, nil

}
