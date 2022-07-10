package orchestrator

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"math/big"

	"github.com/GridPlus/phonon-client/card"
	"github.com/GridPlus/phonon-client/cert"
	"github.com/GridPlus/phonon-client/chain"
	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/tlv"
	remote "github.com/GridPlus/phonon-client/remote/v1/client"
	"github.com/GridPlus/phonon-client/util"

	log "github.com/sirupsen/logrus"
)

var ErrorRequestNotRecognized = errors.New("Unrecognized request sent to session")

/*The session struct handles a local connection with a card
Keeps a client side cache of the card state to make interaction
with the card through this API more convenient*/
type Session struct {
	cs                    model.PhononCard
	RemoteCard            model.CounterpartyPhononCard
	identityPubKey        *ecdsa.PublicKey
	remoteMessageChan     chan (model.SessionRequest)
	remoteMessageKillChan chan interface{}
	active                bool
	pinInitialized        bool
	terminalPaired        bool
	pinVerified           bool
	Cert                  *cert.CardCertificate
	ElementUsageMtex      sync.Mutex
	logger                *log.Entry
	chainSrv              chain.ChainService
}

var ErrAlreadyInitialized = errors.New("card is already initialized with a pin")
var ErrInitFailed = errors.New("card failed initialized check after init command accepted")
var ErrCardNotPairedToCard = errors.New("card not paired with any other card")

//Creates a new card session, automatically connecting if the card is already initialized with a PIN
//The next step is to run VerifyPIN to gain access to the secure commands on the card
func NewSession(storage model.PhononCard) (s *Session, err error) {
	chainSrv, err := chain.NewMultiChainRouter()
	if err != nil {
		return nil, err
	}
	s = &Session{
		cs:                    storage,
		RemoteCard:            nil,
		identityPubKey:        &ecdsa.PublicKey{},
		remoteMessageChan:     make(chan model.SessionRequest),
		remoteMessageKillChan: make(chan interface{}),
		active:                true,
		pinInitialized:        false,
		terminalPaired:        false,
		pinVerified:           false,
		Cert:                  nil,
		ElementUsageMtex:      sync.Mutex{},
		logger:                log.WithField("CardID", "unknown"),
		chainSrv:              chainSrv,
	}
	s.logger = log.WithField("cardID", s.GetName())

	s.ElementUsageMtex.Lock()
	_, _, s.pinInitialized, err = s.cs.Select()
	s.ElementUsageMtex.Unlock()
	if err != nil {
		log.Error("cannot select card for new session: ", err)
		return nil, err
	}
	if !s.pinInitialized {
		return s, nil
	}
	//If card is already initialized, go ahead and open terminal to card secure channel
	err = s.Connect()
	if err != nil {
		log.Error("could not run session connect: ", err)
		return nil, err
	}
	// launch session request handler
	go s.handleIncomingSessionRequests()
	log.Debug("initialized new applet session")
	return s, nil
}

// loop until killed
func (s *Session) handleIncomingSessionRequests() {
	for {
		select {
		case req := <-s.remoteMessageChan:
			s.handleRequest(req)
		case <-s.remoteMessageKillChan:
			return
		}
	}
}

func (s *Session) SetPaired(status bool) {
}

func (s *Session) GetName() string {
	if s.Cert == nil {
		return "unknown"
	}
	if s.Cert.PubKey != nil {
		return util.CardIDFromPubKey(s.identityPubKey)
	}
	return "unknown"
}

func (s *Session) GetCertificate() (*cert.CardCertificate, error) {
	if s.Cert != nil {
		log.Debugf("GetCertificate returning cert: %v", s.Cert)
		return s.Cert, nil
	}

	return &cert.CardCertificate{}, errors.New("certificate not cached by session yet")
}

func (s *Session) IsUnlocked() bool {

	return s.pinVerified
}

func (s *Session) IsInitialized() bool {
	return s.pinInitialized
}

func (s *Session) IsPairedToCard() bool {
	return s.RemoteCard != nil
}

//Connect opens a secure channel with a card.
func (s *Session) Connect() error {
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()
	cert, err := s.cs.Pair()
	if err != nil {
		return err
	}
	s.Cert = cert
	s.identityPubKey, _ = util.ParseECCPubKey(s.Cert.PubKey)
	err = s.cs.OpenSecureChannel()
	if err != nil {
		return err
	}
	s.terminalPaired = true
	return nil
}

//Initializes the card with a PIN
//Also creates a secure channel and verifies the PIN that was just set
func (s *Session) Init(pin string) error {
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	if s.pinInitialized {
		return ErrAlreadyInitialized
	}
	err := s.cs.Init(pin)
	if err != nil {
		return err
	}
	s.pinInitialized = true
	//Open new secure connection now that card is initialized
	err = s.Connect()
	if err != nil {
		return err
	}
	s.pinVerified = true

	return nil
}

func (s *Session) VerifyPIN(pin string) error {
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	err := s.cs.VerifyPIN(pin)
	if err != nil {
		return err
	}
	s.pinVerified = true
	return nil
}

func (s *Session) ChangePIN(pin string) error {
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	if !s.pinVerified {
		return errors.New("card locked, cannot change pin")
	}
	return s.cs.ChangePIN(pin)
}

func (s *Session) verified() bool {
	if s.pinVerified && s.terminalPaired {
		return true
	}
	return false
}

func (s *Session) CreatePhonon() (keyIndex uint16, pubkey model.PhononPubKey, err error) {
	if !s.verified() {
		return 0, nil, card.ErrPINNotEntered
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	return s.cs.CreatePhonon(model.Secp256k1)
}

func (s *Session) CreatePhononWithSetDescriptor(p *model.Phonon, privKey string) (keyIndex uint16, pubkey model.PhononPubKey, err error) {

	if !s.verified() {
		return 0, nil, card.ErrPINNotEntered
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	return s.cs.CreatePhononWithSetDescriptor(model.Secp256k1, p, privKey)
}

func (s *Session) SetDescriptor(p *model.Phonon) error {
	if !s.verified() {
		return card.ErrPINNotEntered
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()
	return s.cs.SetDescriptor(p)
}

func (s *Session) ListPhonons(currencyType model.CurrencyType, lessThanValue uint64, greaterThanValue uint64) ([]*model.Phonon, error) {
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	return s.cs.ListPhonons(currencyType, lessThanValue, greaterThanValue, false)
}

func (s *Session) GetPhononPubKey(keyIndex uint16, crv model.CurveType) (pubkey model.PhononPubKey, err error) {
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	return s.cs.GetPhononPubKey(keyIndex, crv)
}

func (s *Session) DestroyPhonon(keyIndex uint16) (privKey *ecdsa.PrivateKey, err error) {
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	return s.cs.DestroyPhonon(keyIndex)
}

func (s *Session) IdentifyCard(nonce []byte) (cardPubKey *ecdsa.PublicKey, cardSig *util.ECDSASignature, err error) {
	if !s.verified() {
		return nil, nil, card.ErrPINNotEntered
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	return s.cs.IdentifyCard(nonce)
}

func (s *Session) IdentifyPostedPhononNonce() (nonce uint64, err error) {
	if !s.verified() {
		return 0, card.ErrPINNotEntered
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	return s.cs.IdentifyPostedPhononNonce()
}

func (s *Session) InitCardPairing(receiverCert cert.CardCertificate) ([]byte, error) {
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	return s.cs.InitCardPairing(receiverCert)
}

func (s *Session) CardPair(initPairingData []byte) ([]byte, error) {
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	return s.cs.CardPair(initPairingData)
}

func (s *Session) CardPair2(cardPairData []byte) (cardPair2Data []byte, err error) {
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	cardPair2Data, err = s.cs.CardPair2(cardPairData)
	if err != nil {
		return nil, err
	}
	log.Debug("set card session paired")
	return cardPair2Data, nil
}

func (s *Session) FinalizeCardPair(cardPair2Data []byte) error {
	if !s.verified() {
		return card.ErrPINNotEntered
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	err := s.cs.FinalizeCardPair(cardPair2Data)
	if err != nil {
		return err
	}
	return nil
}

func (s *Session) SendPhonons(keyIndices []uint16) error {
	log.Debug("Sending phonons")
	if !s.verified() && s.RemoteCard != nil {
		return ErrCardNotPairedToCard
	}
	log.Debug("verifying pairing")
	err := s.RemoteCard.VerifyPaired()
	if err != nil {
		return err
	}
	log.Debug("locking mutex")
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()
	phononTransferPacket, err := s.cs.SendPhonons(keyIndices, false)
	if err != nil {
		return err
	}
	err = s.RemoteCard.ReceivePhonons(phononTransferPacket)
	if err != nil {
		log.Debug("error receiving phonons on remote")
		return err
	}
	fmt.Println("unlockingMutex")
	return nil
}

func (s *Session) PostPhonons(pubkey []byte, nonce uint64, keyIndices []uint16) (transferPhononPackets []byte, err error) {
	log.Debug("sending orchestrator POST_PHONONS for mock card")

	transferPhononPackets, err = s.cs.PostPhonons(pubkey, nonce, keyIndices)
	if err != nil {
		return nil, err
	}
	return transferPhononPackets, nil
}

func (s *Session) SendFlexPhonon(keyIndexSender uint16, value uint64) (err error) {
	log.Debug("initiating orchestrator Flexing phonons")

	// Initiated by Sending Party
	if !s.verified() && s.RemoteCard != nil {
		return ErrCardNotPairedToCard
	}

	// Verify Pairing
	err = s.RemoteCard.VerifyPaired()
	if err != nil {
		return err
	}

	// check that value is greater than 0
	if (value < 0) {
		return errors.New("flex value must not be negative")
	}

	var setCurrencyType model.CurrencyType = 4
	var lessThanValue uint64
	var greaterThanValue uint64

	// check sending phonon
	// TODO: see if you can access s.cs.Phonons[keyIndexSender]
	sendingPhonons, err := s.cs.ListPhonons(setCurrencyType, lessThanValue, greaterThanValue, false)

	// check currency type
	if (sendingPhonons[keyIndexSender].CurrencyType != 4) {
		return errors.New("only flex phonons may may flexed")
	}

	// check sending phonon has enough value
	if (sendingPhonons[keyIndexSender].Denomination.Value().Cmp(new(big.Int).SetUint64(value)) == -1) {
			return errors.New("sending phonon does not have enough value to flex")
	}

	// get phonon public key for payload
	sendPhononPublicKey := sendingPhonons[keyIndexSender].PubKey
	log.Debug(sendPhononPublicKey)

	// get source public key from phonon tag for payload
	sendTLVs := tlv.EncodeTLVList(sendingPhonons[keyIndexSender].ExtendedTLV...)
	sendCollection, err := tlv.ParseTLVPacket(sendTLVs)
	if err != nil {
			return err
	}
	sendTagPubKey, err := sendCollection.FindTag(model.TagCreatorPublicKey)
	if err != nil {
			return err
	}

	// TODO: check if receiving card has phonon with same sendTagPubKey
	hasPhononMatch, err := s.RemoteCard.FindFlexPhonon(sendTagPubKey)
	if err != nil {
		log.Debug("error looking for flex phonon on remote card")
		return err
	}
	if (hasPhononMatch == false) {
		return errors.New("remote card does not have a flexible phonon with matching source pubkey")
	}

	log.Debug("locking mutex")
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()


	// sending party preps flexible phonon
	var keyIndices []uint16
	keyIndices = append(keyIndices,uint16(keyIndexSender))
	phononTransferPacket, err := s.cs.SendPhonons(keyIndices, false)
	if err != nil {
		return err
	}

	// sending party builds entire payload
	var payload []byte
	payload = append(payload, sendPhononPublicKey.Bytes()[:]...)
	payload = append(payload, sendTagPubKey[:]...)
	payload = append(payload, util.Uint64ToBytes(value)[:]...)
	payload = append(payload, phononTransferPacket[:]...)

	// receiving party receives and handles payload
	returnLoad, err := s.RemoteCard.ReceiveFlexPhonons(payload)
	if err != nil {
		log.Debug("error receiving phonons on remote")
		return err
	}

	// sending party gets their phonon back with updated value
	err = s.cs.ReceivePhonons(returnLoad)

	return nil
}

func (s *Session) ResolveFlexPhonons(payload []byte) (returnLoad []byte, err error) {
	log.Debug("sending BALANCE_PHONONS")

	if !s.verified() && s.RemoteCard != nil {
		return nil, ErrCardNotPairedToCard
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	// receiving party parses payload
	var sendPhononPublicKey = payload[:65]
	var sendTagPubKey = payload[65:130]
	var valueBytes = payload[130:138]
	var phononTransferPacket = payload[138:len(payload)]

	// receiving party gets senders phonon
	err = s.cs.ReceivePhonons(phononTransferPacket)

	var setCurrencyType model.CurrencyType = 4
	var lessThanValue uint64
	var greaterThanValue uint64

	var keepKeyIndex uint16
	var sendKeyIndex uint16

	// receiving party identifies relevant phonons
	receiversPhonons, err := s.cs.ListPhonons(setCurrencyType, lessThanValue, greaterThanValue, false)
	for _, phonon := range receiversPhonons {
		recvrTLVs := tlv.EncodeTLVList(phonon.ExtendedTLV...)
		recvrCollection, err := tlv.ParseTLVPacket(recvrTLVs)
		if err != nil {
				return nil, err
		}
		recvrTagPubKey, err := recvrCollection.FindTag(model.TagCreatorPublicKey)
		if err != nil {
				return nil, err
		}

		// phonon has matching source pub key
		if (string(sendTagPubKey) == string(recvrTagPubKey)) {
			if (string(phonon.PubKey.Bytes()) == string(sendPhononPublicKey)) {
				// this phonon must be sent back to sender
				sendKeyIndex = phonon.KeyIndex
			} else {
				keepKeyIndex = phonon.KeyIndex
			}
		}
	}

	// receiving party updates identified flexible phonons
	value, err := util.BytesToUint64(valueBytes)
	if err != nil {
		return nil, err
	}
	err = s.cs.UpdateFlexPhonons(sendKeyIndex, keepKeyIndex, value)
	if err != nil {
		return nil, err
	}


	// receiving party returns the senders flexible phonon
	var keyIndices []uint16
	keyIndices = append(keyIndices, sendKeyIndex)
	returnLoad, err = s.cs.SendPhonons(keyIndices, false)
	if err != nil {
		return nil, err
	}

	return returnLoad, nil
}

func (s *Session) FindFlexPhonon(TagCreatorPublicKeyBytes []byte) (returnLoad bool, err error) {
	log.Debug("sending FIND_FLEX_PHONON")

	var setCurrencyType model.CurrencyType = 4
	var lessThanValue uint64
	var greaterThanValue uint64

	// look for phonon with matching source public key in tlv
	returnLoad = false
	receiversPhonons, err := s.cs.ListPhonons(setCurrencyType, lessThanValue, greaterThanValue, false)
	for _, phonon := range receiversPhonons {
		recvrTLVs := tlv.EncodeTLVList(phonon.ExtendedTLV...)
		recvrCollection, err := tlv.ParseTLVPacket(recvrTLVs)
		if err != nil {
				return false, err
		}
		recvrTagPubKey, err := recvrCollection.FindTag(model.TagCreatorPublicKey)
		if err != nil {
				return false, err
		}

		// check for matching source pub key
		if (string(TagCreatorPublicKeyBytes) == string(recvrTagPubKey)) {
			log.Debug("found eligible phonon with source pubkey match")
			returnLoad = true
		}
	}
	return returnLoad, nil
}

func (s *Session) ReceivePostedPhonons(postedPacket []byte) (err error) {
	log.Debug("sending orchestrator RECEIVE_POSTED_PHONONS for mock card")

	err = s.cs.ReceivePostedPhonons(postedPacket)
	if err != nil {
		return err
	}
	return nil
}

func (s *Session) ReceivePhonons(phononTransferPacket []byte) error {
	if !s.verified() && s.RemoteCard != nil {
		return ErrCardNotPairedToCard
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	err := s.cs.ReceivePhonons(phononTransferPacket)
	if err != nil {
		return err
	}
	return nil
}

func (s *Session) GenerateInvoice() ([]byte, error) {
	if !s.verified() && s.RemoteCard != nil {
		return nil, ErrCardNotPairedToCard
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	return s.cs.GenerateInvoice()
}

func (s *Session) ReceiveInvoice(invoiceData []byte) error {
	if !s.verified() && s.RemoteCard != nil {
		return ErrCardNotPairedToCard
	}
	s.ElementUsageMtex.Lock()
	defer s.ElementUsageMtex.Unlock()

	err := s.cs.ReceiveInvoice(invoiceData)
	if err != nil {
		return err
	}
	return nil
}

func (s *Session) ConnectToRemoteProvider(RemoteURL string) error {
	u, err := url.Parse(RemoteURL)
	if err != nil {
		return fmt.Errorf("unable to parse url for card connection: %s", err.Error())
	}
	log.Info("connecting")
	remConn, err := remote.Connect(s.remoteMessageChan, fmt.Sprintf("https://%s/phonon", u.Host), true)
	if err != nil {
		return fmt.Errorf("unable to connect to remote session: %s", err.Error())
	}
	s.RemoteCard = remConn
	return nil
}

func (s *Session) RemoteConnectionStatus() model.RemotePairingStatus {
	if s.RemoteCard == nil {
		return model.StatusUnconnected
	}
	return s.RemoteCard.PairingStatus()
}

func (s *Session) ConnectToLocalProvider() error {
	lcp := &localCounterParty{
		localSession:  s,
		pairingStatus: model.StatusConnectedToBridge,
	}
	s.RemoteCard = lcp
	connectedCardsAndLCPSessions[s] = lcp
	return nil
}

func (s *Session) ConnectToCounterparty(cardID string) error {
	err := s.RemoteCard.ConnectToCard(cardID)
	if err != nil {
		log.Info("returning error from ConnectRemoteSession")
		return err
	}
	_, err = util.ParseECCPubKey(s.Cert.PubKey)
	if err != nil {
		//we shouldn't get this far and still receive this error
		return err
	}
	err = s.PairWithRemoteCard(s.RemoteCard)
	return err

}

func (s *Session) PairWithRemoteCard(remoteCard model.CounterpartyPhononCard) error {
	remoteCert, err := remoteCard.GetCertificate()
	if err != nil {
		return err
	}
	initPairingData, err := s.InitCardPairing(*remoteCert)
	if err != nil {
		return err
	}
	log.Debug("sending card pair request")
	cardPairData, err := remoteCard.CardPair(initPairingData)
	if err != nil {
		return err
	}
	cardPair2Data, err := s.CardPair2(cardPairData)
	if err != nil {
		log.Debug("PairWithRemoteCard failed at cardPair2. err: ", err)
		return err
	}
	err = remoteCard.FinalizeCardPair(cardPair2Data)
	if err != nil {
		return err
	}
	s.RemoteCard = remoteCard
	return nil
}

/*InitDepositPhonons takes a currencyType and a map of denominations to quantity,
Creates the required phonons, deposits them using the configured service for the asset
and upon success sets their descriptors*/
func (s *Session) InitDepositPhonons(currencyType model.CurrencyType, denoms []*model.Denomination) (phonons []*model.Phonon, err error) {
	log.Debugf("running InitDepositPhonons with data: %v, %v\n", currencyType, denoms)
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	for _, denom := range denoms {
		p := &model.Phonon{}
		p.KeyIndex, p.PubKey, err = s.CreatePhonon()
		log.Debug("ran CreatePhonons in InitDepositLoop")
		if err != nil {
			log.Error("failed to create phonon for deposit: ", err)
			return nil, err
		}
		p.Denomination = *denom
		p.CurrencyType = currencyType
		p.Address, err = s.chainSrv.DeriveAddress(p)
		if err != nil {
			log.Error("failed to derive address for phonon deposit: ", err)
			return nil, err
		}

		phonons = append(phonons, p)
	}
	return phonons, nil
}

//Phonon Deposit and Redeem higher level methods
type DepositConfirmation struct {
	Phonon           *model.Phonon
	ConfirmedOnChain bool
	ConfirmedOnCard  bool
}

func (s *Session) FinalizeDepositPhonons(confirmations []DepositConfirmation) ([]DepositConfirmation, error) {
	log.Debug("running finalizeDepositPhonon")
	if !s.verified() {
		return nil, card.ErrPINNotEntered
	}
	var lastErr error
	for _, v := range confirmations {
		err := s.FinalizeDepositPhonon(v)
		if err != nil {
			lastErr = err
			v.ConfirmedOnCard = false
		} else {
			v.ConfirmedOnCard = true
		}
	}
	return confirmations, lastErr
}

func (s *Session) FinalizeDepositPhonon(dc DepositConfirmation) error {
	if dc.ConfirmedOnChain {

		err := s.SetDescriptor(dc.Phonon)
		if err != nil {
			log.Error("unable to finalize deposit by setting descriptor for phonon: ", dc.Phonon)
			return err
		}
	} else {
		_, err := s.DestroyPhonon(dc.Phonon.KeyIndex)
		if err != nil {
			log.Error("unable to clean up deposit failure by destroying phonon: ", dc.Phonon)
		}
	}
	return nil
}

// the panics are paths that should NEVER be found in runtime as it's already been determined by the case statement.
func (s *Session) handleRequest(r model.SessionRequest) {
	switch r.GetName() {
	case "RequestCertificate":
		req, ok := r.(*model.RequestCertificate)
		if !ok {
			panic("this shouldn't happen.")
		}
		var resp model.ResponseCertificate
		resp.Payload, resp.Err = s.GetCertificate()
		req.Ret <- resp
	case "RequestIdentifyCard":
		req, ok := r.(*model.RequestIdentifyCard)
		if !ok {
			panic("this shouldn't happen.")
		}
		var resp model.ResponseIdentifyCard
		resp.PubKey, resp.Sig, resp.Err = s.IdentifyCard(req.Nonce)
		req.Ret <- resp
	case "RequestCardPair1":
		req, ok := r.(*model.RequestCardPair1)
		if !ok {
			panic("this shouldn't happen.")
		}
		var resp model.ResponseCardPair1
		resp.Payload, resp.Err = s.CardPair(req.Payload)
		req.Ret <- resp
	case "RequestFinalizeCardPair":
		req, ok := r.(*model.RequestFinalizeCardPair)
		if !ok {
			panic("this shouldn't happen.")
		}
		var resp model.ResponseFinalizeCardPair
		resp.Err = s.FinalizeCardPair(req.Payload)
		req.Ret <- resp

	case "RequestSetRemote":
		req, ok := r.(*model.RequestSetRemote)
		if !ok {
			panic("this shouldn't happen.")
		}
		s.RemoteCard = req.Card
		var resp model.ResponseSetRemote
		resp.Err = nil
		req.Ret <- resp
	case "RequestReceivePhonons":
		req, ok := r.(*model.RequestReceivePhonons)
		if !ok {
			panic("this shouldn't happen.")
		}
		var resp model.ResponseReceivePhonons
		resp.Err = s.ReceivePhonons(req.Payload)
		req.Ret <- resp
	case "RequestFlexPhonons":
		req, ok := r.(*model.RequestFlexPhonons)
		if !ok {
			panic("this shouldn't happen.")
		}
		var resp model.ResponseFlexPhonons
		returnLoad, err := s.ResolveFlexPhonons(req.Payload)
		resp.Returnload = returnLoad
		resp.Err = err
		req.Ret <- resp
	case "RequestFindFlexPhonon":
		req, ok := r.(*model.RequestFindFlexPhonon)
		if !ok {
			panic("this shouldn't happen.")
		}
		var resp model.ResponseFindFlexPhonon
		returnLoad, err := s.FindFlexPhonon(req.Payload)
		resp.Returnload = returnLoad
		resp.Err = err
		req.Ret <- resp
	case "RequestGetName":
		req, ok := r.(*model.RequestGetName)
		if !ok {
			panic("this shouldn't happen.")
		}
		var resp model.ResponseGetName
		resp.Name = s.GetName()
		resp.Err = nil
		req.Ret <- resp
	case "RequestPairWithRemote":
		req, ok := r.(*model.RequestPairWithRemote)
		if !ok {
			panic("this shouldn't happen.")
		}
		var resp model.ResponsePairWithRemote
		resp.Err = s.PairWithRemoteCard(req.Card)
		log.Debug("Returning pairing stuff")
		req.Ret <- resp
		log.Debug("Done returning pairing stuff")
	case "RequestSetPaired":
		req, ok := r.(*model.RequestSetPaired)
		if !ok {
			panic("this shouldn't happen.")
		}
		var resp model.ResponseSetPaired
		s.SetPaired(req.Status)
		resp.Err = nil
		req.Ret <- resp
	}
}

/*RedeemPhonon takes a phonon and a redemptionAddress as an asset specific address string (usually hex encoded)
and submits a transaction to the asset's chain in order to transfer it to another address
In case the on chain transfer fails, returns the private key as a fallback so that access to the asset is not lost*/
func (s *Session) RedeemPhonon(p *model.Phonon, redeemAddress string) (transactionData string, privKeyString string, err error) {
	//Retrieve phonon private key.
	privKey, err := s.DestroyPhonon(p.KeyIndex)
	if err != nil {
		return "", "", err
	}
	privKeyString = util.ECCPrivKeyToHex(privKey)
	transactionData, err = s.chainSrv.RedeemPhonon(p, privKey, redeemAddress)
	if err != nil {
		return "", privKeyString, err
	}

	return transactionData, privKeyString, nil
}

//TODO: retry and track progress automatically.
