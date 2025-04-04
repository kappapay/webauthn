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

package fidou2f

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/kappapay/webauthn"
)

var (
	// Test data from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestation1 = `{
		"rawId": "Bo-VjHOkJZy8DjnCJnIc0Oxt9QAz5upMdSJxNbd-GyAo6MNIvPBb9YsUlE0ZJaaWXtWH5FQyPS6bT_e698IirQ==",
		"id":    "Bo-VjHOkJZy8DjnCJnIc0Oxt9QAz5upMdSJxNbd-GyAo6MNIvPBb9YsUlE0ZJaaWXtWH5FQyPS6bT_e698IirQ==",
		"response": {
			"attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAO-683ISJhKdmUPmVbQuYZsp8lkD7YJcInHS3QOfbrioAiEAzgMJ499cBczBw826r1m55Jmd9mT4d1iEXYS8FbIn8MpjeDVjgVkCSDCCAkQwggEuoAMCAQICBFVivqAwCwYJKoZIhvcNAQELMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAqMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAxNDMyNTM0Njg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESzMfdz2BRLmZXL5FhVF-F1g6pHYjaVy-haxILIAZ8sm5RnrgRbDmbxMbLqMkPJH9pgLjGPP8XY0qerrnK9FDCaM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwCwYJKoZIhvcNAQELA4IBAQCsFtmzbrazqbdtdZSzT1n09z7byf3rKTXra0Ucq_QdJdPnFhTXRyYEynKleOMj7bdgBGhfBefRub4F226UQPrFz8kypsr66FKZdy7bAnggIDzUFB0-629qLOmeOVeAMmOrq41uxICn3whK0sunt9bXfJTD68CxZvlgV8r1_jpjHqJqQzdio2--z0z0RQliX9WvEEmqfIvHaJpmWemvXejw1ywoglF0xQ4Gq39qB5CDe22zKr_cvKg1y7sJDvHw2Z4Iab_p5WdkxCMObAV3KbAQ3g7F-czkyRwoJiGOqAgau5aRUewWclryqNled5W8qiJ6m5RDIMQnYZyq-FTZgpjXaGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAAABABo-VjHOkJZy8DjnCJnIc0Oxt9QAz5upMdSJxNbd-GyAo6MNIvPBb9YsUlE0ZJaaWXtWH5FQyPS6bT_e698IiraUBAgMmIAEhWCA1c9AIeH5sN6x1Q-2qR7v255tkeGbWs0ECCDw35kJGBCJYIBjTUxruadjFFMnWlR5rPJr23sBJT9qexY9PCc9o8hmT",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJWdTh1RHFua3dPamQ4M0tMajZTY24yQmdGTkxGYkdSN0txX1hKSndRbm5hdHp0VVI3WElCTDdLOHVNUENJYVFtS3cxTUNWUTVhYXpOSkZrN05ha2dxQSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
		},
		"type": "public-key"
	}`
	attestation1Sig = []byte{
		0x30, 0x46, 0x02, 0x21, 0x00, 0xEF, 0xBA, 0xF3, 0x72, 0x12, 0x26, 0x12, 0x9D, 0x99, 0x43, 0xE6,
		0x55, 0xB4, 0x2E, 0x61, 0x9B, 0x29, 0xF2, 0x59, 0x03, 0xED, 0x82, 0x5C, 0x22, 0x71, 0xD2, 0xDD,
		0x03, 0x9F, 0x6E, 0xB8, 0xA8, 0x02, 0x21, 0x00, 0xCE, 0x03, 0x09, 0xE3, 0xDF, 0x5C, 0x05, 0xCC,
		0xC1, 0xC3, 0xCD, 0xBA, 0xAF, 0x59, 0xB9, 0xE4, 0x99, 0x9D, 0xF6, 0x64, 0xF8, 0x77, 0x58, 0x84,
		0x5D, 0x84, 0xBC, 0x15, 0xB2, 0x27, 0xF0, 0xCA,
	}
	attestation1CredCert = []byte{
		0x30, 0x82, 0x02, 0x44, 0x30, 0x82, 0x01, 0x2E, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x55,
		0x62, 0xBE, 0xA0, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
		0x30, 0x2E, 0x31, 0x2C, 0x30, 0x2A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x23, 0x59, 0x75, 0x62,
		0x69, 0x63, 0x6F, 0x20, 0x55, 0x32, 0x46, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41, 0x20,
		0x53, 0x65, 0x72, 0x69, 0x61, 0x6C, 0x20, 0x34, 0x35, 0x37, 0x32, 0x30, 0x30, 0x36, 0x33, 0x31,
		0x30, 0x20, 0x17, 0x0D, 0x31, 0x34, 0x30, 0x38, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x5A, 0x18, 0x0F, 0x32, 0x30, 0x35, 0x30, 0x30, 0x39, 0x30, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x5A, 0x30, 0x2A, 0x31, 0x28, 0x30, 0x26, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1F, 0x59,
		0x75, 0x62, 0x69, 0x63, 0x6F, 0x20, 0x55, 0x32, 0x46, 0x20, 0x45, 0x45, 0x20, 0x53, 0x65, 0x72,
		0x69, 0x61, 0x6C, 0x20, 0x31, 0x34, 0x33, 0x32, 0x35, 0x33, 0x34, 0x36, 0x38, 0x38, 0x30, 0x59,
		0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48,
		0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x4B, 0x33, 0x1F, 0x77, 0x3D, 0x81, 0x44,
		0xB9, 0x99, 0x5C, 0xBE, 0x45, 0x85, 0x51, 0x7E, 0x17, 0x58, 0x3A, 0xA4, 0x76, 0x23, 0x69, 0x5C,
		0xBE, 0x85, 0xAC, 0x48, 0x2C, 0x80, 0x19, 0xF2, 0xC9, 0xB9, 0x46, 0x7A, 0xE0, 0x45, 0xB0, 0xE6,
		0x6F, 0x13, 0x1B, 0x2E, 0xA3, 0x24, 0x3C, 0x91, 0xFD, 0xA6, 0x02, 0xE3, 0x18, 0xF3, 0xFC, 0x5D,
		0x8D, 0x2A, 0x7A, 0xBA, 0xE7, 0x2B, 0xD1, 0x43, 0x09, 0xA3, 0x3B, 0x30, 0x39, 0x30, 0x22, 0x06,
		0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x02, 0x04, 0x15, 0x31, 0x2E, 0x33, 0x2E,
		0x36, 0x2E, 0x31, 0x2E, 0x34, 0x2E, 0x31, 0x2E, 0x34, 0x31, 0x34, 0x38, 0x32, 0x2E, 0x31, 0x2E,
		0x35, 0x30, 0x13, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x02, 0x01, 0x01,
		0x04, 0x04, 0x03, 0x02, 0x05, 0x20, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
		0x01, 0x01, 0x0B, 0x03, 0x82, 0x01, 0x01, 0x00, 0xAC, 0x16, 0xD9, 0xB3, 0x6E, 0xB6, 0xB3, 0xA9,
		0xB7, 0x6D, 0x75, 0x94, 0xB3, 0x4F, 0x59, 0xF4, 0xF7, 0x3E, 0xDB, 0xC9, 0xFD, 0xEB, 0x29, 0x35,
		0xEB, 0x6B, 0x45, 0x1C, 0xAB, 0xF4, 0x1D, 0x25, 0xD3, 0xE7, 0x16, 0x14, 0xD7, 0x47, 0x26, 0x04,
		0xCA, 0x72, 0xA5, 0x78, 0xE3, 0x23, 0xED, 0xB7, 0x60, 0x04, 0x68, 0x5F, 0x05, 0xE7, 0xD1, 0xB9,
		0xBE, 0x05, 0xDB, 0x6E, 0x94, 0x40, 0xFA, 0xC5, 0xCF, 0xC9, 0x32, 0xA6, 0xCA, 0xFA, 0xE8, 0x52,
		0x99, 0x77, 0x2E, 0xDB, 0x02, 0x78, 0x20, 0x20, 0x3C, 0xD4, 0x14, 0x1D, 0x3E, 0xEB, 0x6F, 0x6A,
		0x2C, 0xE9, 0x9E, 0x39, 0x57, 0x80, 0x32, 0x63, 0xAB, 0xAB, 0x8D, 0x6E, 0xC4, 0x80, 0xA7, 0xDF,
		0x08, 0x4A, 0xD2, 0xCB, 0xA7, 0xB7, 0xD6, 0xD7, 0x7C, 0x94, 0xC3, 0xEB, 0xC0, 0xB1, 0x66, 0xF9,
		0x60, 0x57, 0xCA, 0xF5, 0xFE, 0x3A, 0x63, 0x1E, 0xA2, 0x6A, 0x43, 0x37, 0x62, 0xA3, 0x6F, 0xBE,
		0xCF, 0x4C, 0xF4, 0x45, 0x09, 0x62, 0x5F, 0xD5, 0xAF, 0x10, 0x49, 0xAA, 0x7C, 0x8B, 0xC7, 0x68,
		0x9A, 0x66, 0x59, 0xE9, 0xAF, 0x5D, 0xE8, 0xF0, 0xD7, 0x2C, 0x28, 0x82, 0x51, 0x74, 0xC5, 0x0E,
		0x06, 0xAB, 0x7F, 0x6A, 0x07, 0x90, 0x83, 0x7B, 0x6D, 0xB3, 0x2A, 0xBF, 0xDC, 0xBC, 0xA8, 0x35,
		0xCB, 0xBB, 0x09, 0x0E, 0xF1, 0xF0, 0xD9, 0x9E, 0x08, 0x69, 0xBF, 0xE9, 0xE5, 0x67, 0x64, 0xC4,
		0x23, 0x0E, 0x6C, 0x05, 0x77, 0x29, 0xB0, 0x10, 0xDE, 0x0E, 0xC5, 0xF9, 0xCC, 0xE4, 0xC9, 0x1C,
		0x28, 0x26, 0x21, 0x8E, 0xA8, 0x08, 0x1A, 0xBB, 0x96, 0x91, 0x51, 0xEC, 0x16, 0x72, 0x5A, 0xF2,
		0xA8, 0xD9, 0x5E, 0x77, 0x95, 0xBC, 0xAA, 0x22, 0x7A, 0x9B, 0x94, 0x43, 0x20, 0xC4, 0x27, 0x61,
		0x9C, 0xAA, 0xF8, 0x54, 0xD9, 0x82, 0x98, 0xD7,
	}

	// Test data from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	attestation2 = `{
		"rawId": "HRiuOZKJ6yNnBrSnocnFuGgsjcAZICl4-0uEDAQHCIXncWQCkYUBvvUzZQovrxmeB9Qm23hmj6PnzWyoiWtt8w",
		"id":    "HRiuOZKJ6yNnBrSnocnFuGgsjcAZICl4-0uEDAQHCIXncWQCkYUBvvUzZQovrxmeB9Qm23hmj6PnzWyoiWtt8w",
		"response": {
			"attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhANsxYs-ntdvXjEaGTl-T91fmoSQCCzLEmXpzwuIqSrzUAiEA2vnx_cP4Ck9ASruZ7NdCtHKleCfd0NwCHcv2cMj175JjeDVjgVkBQDCCATwwgeSgAwIBAgIKOVGHiTh4UmRUCTAKBggqhkjOPQQDAjAXMRUwEwYDVQQDEwxGVCBGSURPIDAxMDAwHhcNMTQwODE0MTgyOTMyWhcNMjQwODE0MTgyOTMyWjAxMS8wLQYDVQQDEyZQaWxvdEdudWJieS0wLjQuMS0zOTUxODc4OTM4Nzg1MjY0NTQwOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIeOKoi1TAiEYdCsb8XIAncH9Ko9EuGkXEugACIy1mV0fefgs7ZA4hnz5X3CS67eUWgMASZzpwKHVybohhppKGAwCgYIKoZIzj0EAwIDRwAwRAIg6BuIpLPxP_wPNiOJZJiqKKKlBUB2CgCwMYibSjki5S8CIOPFCx-Y1JKxbJ7nDs96PsvjDcRfpynzvswDG_V6VuK0aGF1dGhEYXRhWMSVaQiPHs7jIylUA129ENfK45EwWidRtVm7j9fLsim91EEAAAAAAAAAAAAAAAAAAAAAAAAAAABAHRiuOZKJ6yNnBrSnocnFuGgsjcAZICl4-0uEDAQHCIXncWQCkYUBvvUzZQovrxmeB9Qm23hmj6PnzWyoiWtt86UBAgMmIAEhWCCHjiqItUwIhGHQrG_FyAJ3B_SqPRLhpFxLoAAiMtZldCJYIH3n4LO2QOIZ8-V9wkuu3lFoDAEmc6cCh1cm6IYaaShg",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJwU0c5ejZHZDVtNDhXV3c5ZTAzQUppeGJLaWEweW5FcW03b185S0VrUFkwemNhWGhqbXhvQ2hDNVFSbks0RTZYSVQyUUZjX3VHeWNPNWxVTXlnZVpndyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
		},
		"type": "public-key"
	}`
	attestation2Sig = []byte{
		0x30, 0x46, 0x02, 0x21, 0x00, 0xdb, 0x31, 0x62, 0xcf, 0xa7, 0xb5, 0xdb, 0xd7, 0x8c, 0x46, 0x86,
		0x4e, 0x5f, 0x93, 0xf7, 0x57, 0xe6, 0xa1, 0x24, 0x02, 0x0b, 0x32, 0xc4, 0x99, 0x7a, 0x73, 0xc2,
		0xe2, 0x2a, 0x4a, 0xbc, 0xd4, 0x02, 0x21, 0x00, 0xda, 0xf9, 0xf1, 0xfd, 0xc3, 0xf8, 0x0a, 0x4f,
		0x40, 0x4a, 0xbb, 0x99, 0xec, 0xd7, 0x42, 0xb4, 0x72, 0xa5, 0x78, 0x27, 0xdd, 0xd0, 0xdc, 0x02,
		0x1d, 0xcb, 0xf6, 0x70, 0xc8, 0xf5, 0xef, 0x92,
	}
	attestation2CredCert = []byte{
		0x30, 0x82, 0x01, 0x3c, 0x30, 0x81, 0xe4, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0a, 0x39, 0x51,
		0x87, 0x89, 0x38, 0x78, 0x52, 0x64, 0x54, 0x09, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
		0x3d, 0x04, 0x03, 0x02, 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
		0x0c, 0x46, 0x54, 0x20, 0x46, 0x49, 0x44, 0x4f, 0x20, 0x30, 0x31, 0x30, 0x30, 0x30, 0x1e, 0x17,
		0x0d, 0x31, 0x34, 0x30, 0x38, 0x31, 0x34, 0x31, 0x38, 0x32, 0x39, 0x33, 0x32, 0x5a, 0x17, 0x0d,
		0x32, 0x34, 0x30, 0x38, 0x31, 0x34, 0x31, 0x38, 0x32, 0x39, 0x33, 0x32, 0x5a, 0x30, 0x31, 0x31,
		0x2f, 0x30, 0x2d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x26, 0x50, 0x69, 0x6c, 0x6f, 0x74, 0x47,
		0x6e, 0x75, 0x62, 0x62, 0x79, 0x2d, 0x30, 0x2e, 0x34, 0x2e, 0x31, 0x2d, 0x33, 0x39, 0x35, 0x31,
		0x38, 0x37, 0x38, 0x39, 0x33, 0x38, 0x37, 0x38, 0x35, 0x32, 0x36, 0x34, 0x35, 0x34, 0x30, 0x39,
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
		0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x87, 0x8e, 0x2a, 0x88, 0xb5,
		0x4c, 0x08, 0x84, 0x61, 0xd0, 0xac, 0x6f, 0xc5, 0xc8, 0x02, 0x77, 0x07, 0xf4, 0xaa, 0x3d, 0x12,
		0xe1, 0xa4, 0x5c, 0x4b, 0xa0, 0x00, 0x22, 0x32, 0xd6, 0x65, 0x74, 0x7d, 0xe7, 0xe0, 0xb3, 0xb6,
		0x40, 0xe2, 0x19, 0xf3, 0xe5, 0x7d, 0xc2, 0x4b, 0xae, 0xde, 0x51, 0x68, 0x0c, 0x01, 0x26, 0x73,
		0xa7, 0x02, 0x87, 0x57, 0x26, 0xe8, 0x86, 0x1a, 0x69, 0x28, 0x60, 0x30, 0x0a, 0x06, 0x08, 0x2a,
		0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0xe8, 0x1b,
		0x88, 0xa4, 0xb3, 0xf1, 0x3f, 0xfc, 0x0f, 0x36, 0x23, 0x89, 0x64, 0x98, 0xaa, 0x28, 0xa2, 0xa5,
		0x05, 0x40, 0x76, 0x0a, 0x00, 0xb0, 0x31, 0x88, 0x9b, 0x4a, 0x39, 0x22, 0xe5, 0x2f, 0x02, 0x20,
		0xe3, 0xc5, 0x0b, 0x1f, 0x98, 0xd4, 0x92, 0xb1, 0x6c, 0x9e, 0xe7, 0x0e, 0xcf, 0x7a, 0x3e, 0xcb,
		0xe3, 0x0d, 0xc4, 0x5f, 0xa7, 0x29, 0xf3, 0xbe, 0xcc, 0x03, 0x1b, 0xf5, 0x7a, 0x56, 0xe2, 0xb4,
	}
)

type parseTest struct {
	name         string
	attestation  []byte
	wantSig      []byte
	wantCredCert *x509.Certificate
}

type verifyTest struct {
	name          string
	attestation   []byte
	wantAttType   webauthn.AttestationType
	wantTrustPath interface{}
}

var parseTests = []parseTest{
	{"attestation 1", []byte(attestation1), attestation1Sig, parseCertificate(attestation1CredCert)},
	{"attestation 2", []byte(attestation2), attestation2Sig, parseCertificate(attestation2CredCert)},
}

var verifyTests = []verifyTest{
	{"attestation 1", []byte(attestation1), webauthn.AttestationTypeBasic, []*x509.Certificate{parseCertificate(attestation1CredCert)}},
	{"attestation 2", []byte(attestation2), webauthn.AttestationTypeBasic, []*x509.Certificate{parseCertificate(attestation2CredCert)}},
}

func parseCertificate(data []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(data)
	if err != nil {
		panic(err)
	}
	return c
}

func certificateEqual(c1 *x509.Certificate, c2 *x509.Certificate) bool {
	if c1 == nil && c2 == nil {
		return true
	}
	if (c1 == nil && c2 != nil) || (c1 != nil && c2 == nil) {
		return false
	}
	return bytes.Equal(c1.Raw, c2.Raw)
}

func TestParseFIDOU2FAttestation(t *testing.T) {
	for _, tc := range parseTests {
		t.Run(tc.name, func(t *testing.T) {
			var credentialAttestation webauthn.PublicKeyCredentialAttestation
			if err := json.Unmarshal(tc.attestation, &credentialAttestation); err != nil {
				t.Fatalf("failed to unmarshal attestation %s: %q", string(tc.attestation), err)
			}
			attStmt, ok := credentialAttestation.AttStmt.(*fidou2fAttestationStatement)
			if !ok {
				t.Fatalf("attestation type %T, want *fidou2fAttestationStatement", credentialAttestation.AttStmt)
			}
			if !bytes.Equal(attStmt.sig, tc.wantSig) {
				t.Errorf("attestation sig %v, want %v", attStmt.sig, tc.wantSig)
			}
			if !certificateEqual(attStmt.attestnCert, tc.wantCredCert) {
				t.Errorf("attestation cred cert %v, want %v", attStmt.attestnCert, tc.wantCredCert)
			}
		})
	}
}

func TestVerifyFIDOU2FAttestation(t *testing.T) {
	for _, tc := range verifyTests {
		t.Run(tc.name, func(t *testing.T) {
			var credentialAttestation webauthn.PublicKeyCredentialAttestation
			if err := json.Unmarshal(tc.attestation, &credentialAttestation); err != nil {
				t.Fatalf("failed to unmarshal attestation %s: %q", string(tc.attestation), err)
			}
			attType, trustPath, err := credentialAttestation.VerifyAttestationStatement()
			if err != nil {
				t.Fatalf("VerifyAttestationStatement() returns error %q", err)
			}
			if attType != tc.wantAttType {
				t.Errorf("attestation type %v, want %v", attType, tc.wantAttType)
			}
			if !reflect.DeepEqual(trustPath, tc.wantTrustPath) {
				t.Errorf("trust path %v, want %v", trustPath, tc.wantTrustPath)
			}
		})
	}
}
