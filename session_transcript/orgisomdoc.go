package session_transcript

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type EncryptionParameters struct {
	Nonce              []byte `json:"nonce"`
	RecipientPublicKey string `json:"recipientPublicKey"`
}

func SessionTranscriptOrgIsoMdoc(nonce []byte, recipientPublicKey string) ([]byte, error) {
	encryptionParameters := EncryptionParameters{
		Nonce:              nonce,
		RecipientPublicKey: recipientPublicKey,
	}
	encryptionInfo := []interface{}{
		"dcapi",
		encryptionParameters,
	}
	encryptionInfoBytes, err := cbor.Marshal(encryptionInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encode encryption info: %w", err)
	}
	base64EncryptionInfo := base64.StdEncoding.EncodeToString(encryptionInfoBytes)

	serializedOrigin := "https://digital-credentials.kgoro.click"

	dcapiInfo := []interface{}{
		base64EncryptionInfo,
		serializedOrigin,
	}
	dcapiInfoBytes, err := cbor.Marshal(dcapiInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encode dcapi info: %w", err)
	}

	dcapiInfoHash := sha256.Sum256(dcapiInfoBytes)

	sessionTranscript := []interface{}{
		nil,
		nil,
		[]interface{}{
			"dcapi",
			dcapiInfoHash,
		},
	}

	transcript, err := cbor.Marshal(sessionTranscript)
	if err != nil {
		return nil, fmt.Errorf("failed to encode session transcript: %w", err)
	}
	return transcript, nil
}
