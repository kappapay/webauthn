/*
Copyright 2019-present Faye Amacker.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Modified by Kappa
*/

package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
)

func TestPublicKeyCredentialCreationOptionsJSONMarshal(t *testing.T) {
	options := PublicKeyCredentialCreationOptions{
		RP: PublicKeyCredentialRpEntity{
			Name: "ACME Corporation",
			Icon: "https://acme.com/avatar.png",
			ID:   "acme.com",
		},
		User: PublicKeyCredentialUserEntity{
			Name:        "Jane Doe",
			Icon:        "https://janedoe.com/avatar.png",
			ID:          []byte{1, 2, 3},
			DisplayName: "jane",
		},
		Challenge: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		PubKeyCredParams: []PublicKeyCredentialParameters{
			{Type: "public-key", Alg: -7},
			{Type: "public-key", Alg: -37},
		},
		Timeout: uint64(60000),
		ExcludeCredentials: []PublicKeyCredentialDescriptor{
			{Type: "public-key", ID: []byte{4, 5, 6}, Transports: []AuthenticatorTransport{"usb"}},
			{Type: "public-key", ID: []byte{7, 8, 9}, Transports: []AuthenticatorTransport{"internal"}},
		},
		AuthenticatorSelection: AuthenticatorSelectionCriteria{
			AuthenticatorAttachment: AuthenticatorPlatform,
			RequireResidentKey:      true,
			UserVerification:        UserVerificationRequired,
		},
		Attestation: AttestationDirect,
	}
	b, err := json.Marshal(options)
	if err != nil {
		t.Fatalf("failed to marshal PublicKeyCredentialCreationOptions object to JSON, %q", err)
	}
	var options2 PublicKeyCredentialCreationOptions
	if err = json.Unmarshal(b, &options2); err != nil {
		t.Fatalf("failed to unmarshal PublicKeyCredentialCreationOptions object from JSON, %q", err)
	}
	if !reflect.DeepEqual(options, options2) {
		t.Errorf("json.Unmarshal(%s) returns %+v, want %+v", string(b), options2, options)
	}
}

func TestPublicKeyCredentialRequestOptionsJSONMarshal(t *testing.T) {
	options := PublicKeyCredentialRequestOptions{
		Challenge: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Timeout:   uint64(60000),
		RPID:      "acme.com",
		AllowCredentials: []PublicKeyCredentialDescriptor{
			{Type: "public-key", ID: []byte{4, 5, 6}, Transports: []AuthenticatorTransport{"usb"}},
			{Type: "public-key", ID: []byte{7, 8, 9}, Transports: []AuthenticatorTransport{"internal"}},
		},
		UserVerification: UserVerificationRequired,
	}
	b, err := json.Marshal(options)
	if err != nil {
		t.Fatalf("failed to marshal PublicKeyCredentialRequestOptions object to JSON, %q", err)
	}
	var options2 PublicKeyCredentialRequestOptions
	if err = json.Unmarshal(b, &options2); err != nil {
		t.Fatalf("failed to unmarshal PublicKeyCredentialRequestOptions object from JSON, %q", err)
	}
	if !reflect.DeepEqual(options, options2) {
		t.Errorf("json.Unmarshal(%s) returns %+v, want %+v", string(b), options2, options)
	}
}

// TestBufferStringJSONUnMarshal validates that we can Unmarshal any json encoding to a bufferString
func TestBufferStringJSONUnMarshal(t *testing.T) {
	userID := []byte("\"user-test-1234\"")
	encodings := map[string]string{
		"std":    base64.StdEncoding.EncodeToString(userID),
		"rawStd": base64.RawStdEncoding.EncodeToString(userID),
		"url":    base64.URLEncoding.EncodeToString(userID),
		"rawUrl": base64.RawURLEncoding.EncodeToString(userID),
		"error":  "f##",
	}

	for encodingType, encoding := range encodings {
		id := map[string]string{
			"id": encoding,
		}
		b, err := json.Marshal(id)
		if err != nil {
			t.Fatalf("failed to marshal to json, got err: %v", err)
		}
		var opt PublicKeyCredentialUserEntity
		err = json.Unmarshal(b, &opt)
		if encodingType != "error" {
			if err != nil {
				t.Fatalf("failed to unmarshal %s encoding got err: %v", encodingType, err)
			}
		} else {
			if err == nil {
				t.Fatal("error expected but got none")
			}
		}

	}
}
