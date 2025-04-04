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

package packed

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/kappapay/webauthn"
)

var (
	// Test data from apowers313's fido2-helpers (2019) at https://github.com/apowers313/fido2-helpers/blob/master/fido2-helpers.js
	basicAttestation1 = `{
		"rawId": "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r",
		"id":    "sL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401r",
		"response": {
			"attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAIsK0Wr9tmud-waIYoQw20UWi7DL_gDx_PNG3PB57eHLAiEAtRyd-4JI2pCVX-dDz4mbHc_AkvC3d_4qnBBa3n2I_hVjeDVjg1kCRTCCAkEwggHooAMCAQICEBWfe8LNiRjxKGuTSPqfM-IwCgYIKoZIzj0EAwIwSTELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMRswGQYDVQQDDBJGZWl0aWFuIEZJRE8yIENBLTEwIBcNMTgwNDExMDAwMDAwWhgPMjAzMzA0MTAyMzU5NTlaMG8xCzAJBgNVBAYTAkNOMR0wGwYDVQQKDBRGZWl0aWFuIFRlY2hub2xvZ2llczEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEdMBsGA1UEAwwURlQgQmlvUGFzcyBGSURPMiBVU0IwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASABnVcWfvJSbAVqNIKkliXvoMKsu_oLPiP7aCQlmPlSMcfEScFM7QkRnidTP7hAUOKlOmDPeIALC8qHddvTdtdo4GJMIGGMB0GA1UdDgQWBBR6VIJCgGLYiuevhJglxK-RqTSY8jAfBgNVHSMEGDAWgBRNO9jEZxUbuxPo84TYME-daRXAgzAMBgNVHRMBAf8EAjAAMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEEI4MkVENzNDOEZCNEU1QTIwCgYIKoZIzj0EAwIDRwAwRAIgJEtFo76I3LfgJaLGoxLP-4btvCdKIsEFLjFIUfDosIcCIDQav04cJPILGnPVPazCqfkVtBuyOmsBbx_v-ODn-JDAWQH_MIIB-zCCAaCgAwIBAgIQFZ97ws2JGPEoa5NI-p8z4TAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTE4MDQxMDAwMDAwMFoYDzIwMzgwNDA5MjM1OTU5WjBJMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxGzAZBgNVBAMMEkZlaXRpYW4gRklETzIgQ0EtMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI5-YAnswRZlzKD6w-lv5Qg7lW1XJRHrWzL01mc5V91n2LYXNR3_S7mA5gupuTO5mjQw8xfqIRMHVr1qB3TedY-jZjBkMB0GA1UdDgQWBBRNO9jEZxUbuxPo84TYME-daRXAgzAfBgNVHSMEGDAWgBTRoZhNgX_DuWv2B2e9UBL-kEXxVDASBgNVHRMBAf8ECDAGAQH_AgEAMA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAgNJADBGAiEA-3-j0kBHoRFQwnhWbSHMkBaY7KF_TztINFN5ymDkwmUCIQDrCkPBiMHXvYg-kSRgVsKwuVtYonRvC588qRwpLStZ7FkB3DCCAdgwggF-oAMCAQICEBWfe8LNiRjxKGuTSPqfM9YwCgYIKoZIzj0EAwIwSzELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMR0wGwYDVQQDDBRGZWl0aWFuIEZJRE8gUm9vdCBDQTAgFw0xODA0MDEwMDAwMDBaGA8yMDQ4MDMzMTIzNTk1OVowSzELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFEZlaXRpYW4gVGVjaG5vbG9naWVzMR0wGwYDVQQDDBRGZWl0aWFuIEZJRE8gUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ3wCm47zF9RMtW-pPlkEHTVTLfSYBlsidz7zOAUiuV6k36PvtKAI_-LZ8MiC9BxQUfUrfpLY6klw344lwLq7POjQjBAMB0GA1UdDgQWBBTRoZhNgX_DuWv2B2e9UBL-kEXxVDAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiEAt7E9ZQYxnhfsSk6c1dSmFNnJGoU3eJiycs2DoWh7-IoCIA9iWJH8h-UOAaaPK66DtCLe6GIxdpIMv3kmd1PRpWqsaGF1dGhEYXRhWOSVaQiPHs7jIylUA129ENfK45EwWidRtVm7j9fLsim91EEAAAABQjgyRUQ3M0M4RkI0RTVBMgBgsL39APyTmisrjh11vghaqNfuruLQmCfR0c1ryKtaQ81jkEhNa5u9xLTnkibvXC9YpzBLFwWEZ3k9CR_sxzm_pWYbBOtKxeZu9z2GT8b6QW4iQvRlyumCT3oENx_8401rpQECAyYgASFYIFkdweEE6mWiIAYPDoKz3881Aoa4sn8zkTm0aPKKYBvdIlggtlG32lxrang8M0tojYJ36CL1VMv2pZSzqR_NfvG88bA",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJ1Vlg4OElnUmEwU1NyTUlSVF9xN2NSY2RmZ2ZSQnhDZ25fcGtwVUFuWEpLMnpPYjMwN3dkMU9MWFEwQXVOYU10QlIzYW1rNkhZenAtX1Z4SlRQcHdHdyIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidG9rZW5CaW5kaW5nIjp7InN0YXR1cyI6Im5vdC1zdXBwb3J0ZWQifSwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
		},
		"type": "public-key"
	}`
	basicAttestation1Sig = []byte{
		0x30, 0x46, 0x02, 0x21, 0x00, 0x8B, 0x0A, 0xD1, 0x6A, 0xFD, 0xB6, 0x6B, 0x9D, 0xFB, 0x06, 0x88,
		0x62, 0x84, 0x30, 0xDB, 0x45, 0x16, 0x8B, 0xB0, 0xCB, 0xFE, 0x00, 0xF1, 0xFC, 0xF3, 0x46, 0xDC,
		0xF0, 0x79, 0xED, 0xE1, 0xCB, 0x02, 0x21, 0x00, 0xB5, 0x1C, 0x9D, 0xFB, 0x82, 0x48, 0xDA, 0x90,
		0x95, 0x5F, 0xE7, 0x43, 0xCF, 0x89, 0x9B, 0x1D, 0xCF, 0xC0, 0x92, 0xF0, 0xB7, 0x77, 0xFE, 0x2A,
		0x9C, 0x10, 0x5A, 0xDE, 0x7D, 0x88, 0xFE, 0x15,
	}
	basicAttestation1CredCert = []byte{
		0x30, 0x82, 0x02, 0x41, 0x30, 0x82, 0x01, 0xE8, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x15,
		0x9F, 0x7B, 0xC2, 0xCD, 0x89, 0x18, 0xF1, 0x28, 0x6B, 0x93, 0x48, 0xFA, 0x9F, 0x33, 0xE2, 0x30,
		0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x49, 0x31, 0x0B, 0x30,
		0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03,
		0x55, 0x04, 0x0A, 0x0C, 0x14, 0x46, 0x65, 0x69, 0x74, 0x69, 0x61, 0x6E, 0x20, 0x54, 0x65, 0x63,
		0x68, 0x6E, 0x6F, 0x6C, 0x6F, 0x67, 0x69, 0x65, 0x73, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x03, 0x55,
		0x04, 0x03, 0x0C, 0x12, 0x46, 0x65, 0x69, 0x74, 0x69, 0x61, 0x6E, 0x20, 0x46, 0x49, 0x44, 0x4F,
		0x32, 0x20, 0x43, 0x41, 0x2D, 0x31, 0x30, 0x20, 0x17, 0x0D, 0x31, 0x38, 0x30, 0x34, 0x31, 0x31,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x18, 0x0F, 0x32, 0x30, 0x33, 0x33, 0x30, 0x34, 0x31,
		0x30, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0x30, 0x6F, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
		0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x0A,
		0x0C, 0x14, 0x46, 0x65, 0x69, 0x74, 0x69, 0x61, 0x6E, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6E, 0x6F,
		0x6C, 0x6F, 0x67, 0x69, 0x65, 0x73, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C,
		0x19, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6E, 0x74, 0x69, 0x63, 0x61, 0x74, 0x6F, 0x72, 0x20, 0x41,
		0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03,
		0x55, 0x04, 0x03, 0x0C, 0x14, 0x46, 0x54, 0x20, 0x42, 0x69, 0x6F, 0x50, 0x61, 0x73, 0x73, 0x20,
		0x46, 0x49, 0x44, 0x4F, 0x32, 0x20, 0x55, 0x53, 0x42, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A,
		0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
		0x03, 0x42, 0x00, 0x04, 0x80, 0x06, 0x75, 0x5C, 0x59, 0xFB, 0xC9, 0x49, 0xB0, 0x15, 0xA8, 0xD2,
		0x0A, 0x92, 0x58, 0x97, 0xBE, 0x83, 0x0A, 0xB2, 0xEF, 0xE8, 0x2C, 0xF8, 0x8F, 0xED, 0xA0, 0x90,
		0x96, 0x63, 0xE5, 0x48, 0xC7, 0x1F, 0x11, 0x27, 0x05, 0x33, 0xB4, 0x24, 0x46, 0x78, 0x9D, 0x4C,
		0xFE, 0xE1, 0x01, 0x43, 0x8A, 0x94, 0xE9, 0x83, 0x3D, 0xE2, 0x00, 0x2C, 0x2F, 0x2A, 0x1D, 0xD7,
		0x6F, 0x4D, 0xDB, 0x5D, 0xA3, 0x81, 0x89, 0x30, 0x81, 0x86, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D,
		0x0E, 0x04, 0x16, 0x04, 0x14, 0x7A, 0x54, 0x82, 0x42, 0x80, 0x62, 0xD8, 0x8A, 0xE7, 0xAF, 0x84,
		0x98, 0x25, 0xC4, 0xAF, 0x91, 0xA9, 0x34, 0x98, 0xF2, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23,
		0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x4D, 0x3B, 0xD8, 0xC4, 0x67, 0x15, 0x1B, 0xBB, 0x13, 0xE8,
		0xF3, 0x84, 0xD8, 0x30, 0x4F, 0x9D, 0x69, 0x15, 0xC0, 0x83, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D,
		0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00, 0x30, 0x13, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04,
		0x01, 0x82, 0xE5, 0x1C, 0x02, 0x01, 0x01, 0x04, 0x04, 0x03, 0x02, 0x05, 0x20, 0x30, 0x21, 0x06,
		0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x01, 0x01, 0x04, 0x04, 0x12, 0x04, 0x10,
		0x42, 0x38, 0x32, 0x45, 0x44, 0x37, 0x33, 0x43, 0x38, 0x46, 0x42, 0x34, 0x45, 0x35, 0x41, 0x32,
		0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30,
		0x44, 0x02, 0x20, 0x24, 0x4B, 0x45, 0xA3, 0xBE, 0x88, 0xDC, 0xB7, 0xE0, 0x25, 0xA2, 0xC6, 0xA3,
		0x12, 0xCF, 0xFB, 0x86, 0xED, 0xBC, 0x27, 0x4A, 0x22, 0xC1, 0x05, 0x2E, 0x31, 0x48, 0x51, 0xF0,
		0xE8, 0xB0, 0x87, 0x02, 0x20, 0x34, 0x1A, 0xBF, 0x4E, 0x1C, 0x24, 0xF2, 0x0B, 0x1A, 0x73, 0xD5,
		0x3D, 0xAC, 0xC2, 0xA9, 0xF9, 0x15, 0xB4, 0x1B, 0xB2, 0x3A, 0x6B, 0x01, 0x6F, 0x1F, 0xEF, 0xF8,
		0xE0, 0xE7, 0xF8, 0x90, 0xC0,
	}
	basicAttestation1CACert0 = []byte{
		0x30, 0x82, 0x01, 0xFB, 0x30, 0x82, 0x01, 0xA0, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x15,
		0x9F, 0x7B, 0xC2, 0xCD, 0x89, 0x18, 0xF1, 0x28, 0x6B, 0x93, 0x48, 0xFA, 0x9F, 0x33, 0xE1, 0x30,
		0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x4B, 0x31, 0x0B, 0x30,
		0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03,
		0x55, 0x04, 0x0A, 0x0C, 0x14, 0x46, 0x65, 0x69, 0x74, 0x69, 0x61, 0x6E, 0x20, 0x54, 0x65, 0x63,
		0x68, 0x6E, 0x6F, 0x6C, 0x6F, 0x67, 0x69, 0x65, 0x73, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55,
		0x04, 0x03, 0x0C, 0x14, 0x46, 0x65, 0x69, 0x74, 0x69, 0x61, 0x6E, 0x20, 0x46, 0x49, 0x44, 0x4F,
		0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41, 0x30, 0x20, 0x17, 0x0D, 0x31, 0x38, 0x30, 0x34,
		0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x18, 0x0F, 0x32, 0x30, 0x33, 0x38, 0x30,
		0x34, 0x30, 0x39, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0x30, 0x49, 0x31, 0x0B, 0x30, 0x09,
		0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55,
		0x04, 0x0A, 0x0C, 0x14, 0x46, 0x65, 0x69, 0x74, 0x69, 0x61, 0x6E, 0x20, 0x54, 0x65, 0x63, 0x68,
		0x6E, 0x6F, 0x6C, 0x6F, 0x67, 0x69, 0x65, 0x73, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04,
		0x03, 0x0C, 0x12, 0x46, 0x65, 0x69, 0x74, 0x69, 0x61, 0x6E, 0x20, 0x46, 0x49, 0x44, 0x4F, 0x32,
		0x20, 0x43, 0x41, 0x2D, 0x31, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
		0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
		0x8E, 0x7E, 0x60, 0x09, 0xEC, 0xC1, 0x16, 0x65, 0xCC, 0xA0, 0xFA, 0xC3, 0xE9, 0x6F, 0xE5, 0x08,
		0x3B, 0x95, 0x6D, 0x57, 0x25, 0x11, 0xEB, 0x5B, 0x32, 0xF4, 0xD6, 0x67, 0x39, 0x57, 0xDD, 0x67,
		0xD8, 0xB6, 0x17, 0x35, 0x1D, 0xFF, 0x4B, 0xB9, 0x80, 0xE6, 0x0B, 0xA9, 0xB9, 0x33, 0xB9, 0x9A,
		0x34, 0x30, 0xF3, 0x17, 0xEA, 0x21, 0x13, 0x07, 0x56, 0xBD, 0x6A, 0x07, 0x74, 0xDE, 0x75, 0x8F,
		0xA3, 0x66, 0x30, 0x64, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x4D,
		0x3B, 0xD8, 0xC4, 0x67, 0x15, 0x1B, 0xBB, 0x13, 0xE8, 0xF3, 0x84, 0xD8, 0x30, 0x4F, 0x9D, 0x69,
		0x15, 0xC0, 0x83, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
		0xD1, 0xA1, 0x98, 0x4D, 0x81, 0x7F, 0xC3, 0xB9, 0x6B, 0xF6, 0x07, 0x67, 0xBD, 0x50, 0x12, 0xFE,
		0x90, 0x45, 0xF1, 0x54, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x08,
		0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01,
		0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
		0x3D, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xFB, 0x7F, 0xA3, 0xD2,
		0x40, 0x47, 0xA1, 0x11, 0x50, 0xC2, 0x78, 0x56, 0x6D, 0x21, 0xCC, 0x90, 0x16, 0x98, 0xEC, 0xA1,
		0x7F, 0x4F, 0x3B, 0x48, 0x34, 0x53, 0x79, 0xCA, 0x60, 0xE4, 0xC2, 0x65, 0x02, 0x21, 0x00, 0xEB,
		0x0A, 0x43, 0xC1, 0x88, 0xC1, 0xD7, 0xBD, 0x88, 0x3E, 0x91, 0x24, 0x60, 0x56, 0xC2, 0xB0, 0xB9,
		0x5B, 0x58, 0xA2, 0x74, 0x6F, 0x0B, 0x9F, 0x3C, 0xA9, 0x1C, 0x29, 0x2D, 0x2B, 0x59, 0xEC,
	}
	basicAttestation1CACert1 = []byte{
		0x30, 0x82, 0x01, 0xD8, 0x30, 0x82, 0x01, 0x7E, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x15,
		0x9F, 0x7B, 0xC2, 0xCD, 0x89, 0x18, 0xF1, 0x28, 0x6B, 0x93, 0x48, 0xFA, 0x9F, 0x33, 0xD6, 0x30,
		0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x4B, 0x31, 0x0B, 0x30,
		0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03,
		0x55, 0x04, 0x0A, 0x0C, 0x14, 0x46, 0x65, 0x69, 0x74, 0x69, 0x61, 0x6E, 0x20, 0x54, 0x65, 0x63,
		0x68, 0x6E, 0x6F, 0x6C, 0x6F, 0x67, 0x69, 0x65, 0x73, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55,
		0x04, 0x03, 0x0C, 0x14, 0x46, 0x65, 0x69, 0x74, 0x69, 0x61, 0x6E, 0x20, 0x46, 0x49, 0x44, 0x4F,
		0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41, 0x30, 0x20, 0x17, 0x0D, 0x31, 0x38, 0x30, 0x34,
		0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x18, 0x0F, 0x32, 0x30, 0x34, 0x38, 0x30,
		0x33, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0x30, 0x4B, 0x31, 0x0B, 0x30, 0x09,
		0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55,
		0x04, 0x0A, 0x0C, 0x14, 0x46, 0x65, 0x69, 0x74, 0x69, 0x61, 0x6E, 0x20, 0x54, 0x65, 0x63, 0x68,
		0x6E, 0x6F, 0x6C, 0x6F, 0x67, 0x69, 0x65, 0x73, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04,
		0x03, 0x0C, 0x14, 0x46, 0x65, 0x69, 0x74, 0x69, 0x61, 0x6E, 0x20, 0x46, 0x49, 0x44, 0x4F, 0x20,
		0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48,
		0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42,
		0x00, 0x04, 0x9D, 0xF0, 0x0A, 0x6E, 0x3B, 0xCC, 0x5F, 0x51, 0x32, 0xD5, 0xBE, 0xA4, 0xF9, 0x64,
		0x10, 0x74, 0xD5, 0x4C, 0xB7, 0xD2, 0x60, 0x19, 0x6C, 0x89, 0xDC, 0xFB, 0xCC, 0xE0, 0x14, 0x8A,
		0xE5, 0x7A, 0x93, 0x7E, 0x8F, 0xBE, 0xD2, 0x80, 0x23, 0xFF, 0x8B, 0x67, 0xC3, 0x22, 0x0B, 0xD0,
		0x71, 0x41, 0x47, 0xD4, 0xAD, 0xFA, 0x4B, 0x63, 0xA9, 0x25, 0xC3, 0x7E, 0x38, 0x97, 0x02, 0xEA,
		0xEC, 0xF3, 0xA3, 0x42, 0x30, 0x40, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04,
		0x14, 0xD1, 0xA1, 0x98, 0x4D, 0x81, 0x7F, 0xC3, 0xB9, 0x6B, 0xF6, 0x07, 0x67, 0xBD, 0x50, 0x12,
		0xFE, 0x90, 0x45, 0xF1, 0x54, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04,
		0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF,
		0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04,
		0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xB7, 0xB1, 0x3D, 0x65, 0x06, 0x31,
		0x9E, 0x17, 0xEC, 0x4A, 0x4E, 0x9C, 0xD5, 0xD4, 0xA6, 0x14, 0xD9, 0xC9, 0x1A, 0x85, 0x37, 0x78,
		0x98, 0xB2, 0x72, 0xCD, 0x83, 0xA1, 0x68, 0x7B, 0xF8, 0x8A, 0x02, 0x20, 0x0F, 0x62, 0x58, 0x91,
		0xFC, 0x87, 0xE5, 0x0E, 0x01, 0xA6, 0x8F, 0x2B, 0xAE, 0x83, 0xB4, 0x22, 0xDE, 0xE8, 0x62, 0x31,
		0x76, 0x92, 0x0C, 0xBF, 0x79, 0x26, 0x77, 0x53, 0xD1, 0xA5, 0x6A, 0xAC,
	}

	// Test data from herrjemand's verify.packed.webauthn.js (2019) at https://gist.github.com/herrjemand/dbeb2c2b76362052e5268224660b6fbc
	selfAttestation1 = `{
		"id":    "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14",
		"rawId": "H6X2BnnjgOzu_Oj87vpRnwMJeJYVzwM3wtY1lhAfQ14",
		"response": {
			"attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzn__mNzaWdZAQCPypMLXWqtCZ1sc5QdjhH-pAzm8-adpfbemd5zsym2krscwV0EeOdTrdUOdy3hWj5HuK9dIX_OpNro2jKrHfUj_0Kp-u87iqJ3MPzs-D9zXOqkbWqcY94Zh52wrPwhGfJ8BiQp5T4Q97E042hYQRDKmtv7N-BT6dywiuFHxfm1sDbUZ_yyEIN3jgttJzjp_wvk_RJmb78bLPTlym83Y0Ws73K6FFeiqFNqLA_8a4V0I088hs_IEPlj8PWxW0wnIUhI9IcRf0GEmUwTBpbNDGpIFGOudnl_C3YuXuzK3R6pv2r7m9-9cIIeeYXD9BhSMBQ0A8oxBbVF7j-0xXDNrXHZaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAOKjVmSRjt0nqud40p1PeHgEAIB-l9gZ544Ds7vzo_O76UZ8DCXiWFc8DN8LWNZYQH0NepAEDAzn__iBZAQDAIqzybPPmgeL5OR6JKq9bWDiENJlN_LePQEnf1_sgOm4FJ9kBTbOTtWplfoMXg40A7meMppiRqP72A3tmILwZ5xKIyY7V8Y2t8X1ilYJol2nCKOpAEqGLTRJjF64GQxen0uFpi1tA6l6N-ZboPxjky4aidBdUP22YZuEPCO8-9ZTha8qwvTgZwMHhZ40TUPEJGGWOnHNlYmqnfFfk0P-UOZokI0rqtqqQGMwzV2RrH2kjKTZGfyskAQnrqf9PoJkye4KUjWkWnZzhkZbrDoLyTEX2oWvTTflnR5tAVMQch4UGgEHSZ00G5SFoc19nGx_UJcqezx5cLZsny-qQYDRjIUMBAAE",
			"clientDataJSON":    "eyJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjaGFsbGVuZ2UiOiJBWGtYV1hQUDNnTHg4T0xscGtKM2FSUmhGV250blNFTmdnbmpEcEJxbDFuZ0tvbDd4V3dldlVZdnJwQkRQM0xFdmRyMkVPU3RPRnBHR3huTXZYay1WdyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
		},
		"type": "public-key"
	}`
	selfAttestation1Sig = []byte{
		0x8f, 0xca, 0x93, 0x0b, 0x5d, 0x6a, 0xad, 0x09, 0x9d, 0x6c, 0x73, 0x94, 0x1d, 0x8e, 0x11, 0xfe,
		0xa4, 0x0c, 0xe6, 0xf3, 0xe6, 0x9d, 0xa5, 0xf6, 0xde, 0x99, 0xde, 0x73, 0xb3, 0x29, 0xb6, 0x92,
		0xbb, 0x1c, 0xc1, 0x5d, 0x04, 0x78, 0xe7, 0x53, 0xad, 0xd5, 0x0e, 0x77, 0x2d, 0xe1, 0x5a, 0x3e,
		0x47, 0xb8, 0xaf, 0x5d, 0x21, 0x7f, 0xce, 0xa4, 0xda, 0xe8, 0xda, 0x32, 0xab, 0x1d, 0xf5, 0x23,
		0xff, 0x42, 0xa9, 0xfa, 0xef, 0x3b, 0x8a, 0xa2, 0x77, 0x30, 0xfc, 0xec, 0xf8, 0x3f, 0x73, 0x5c,
		0xea, 0xa4, 0x6d, 0x6a, 0x9c, 0x63, 0xde, 0x19, 0x87, 0x9d, 0xb0, 0xac, 0xfc, 0x21, 0x19, 0xf2,
		0x7c, 0x06, 0x24, 0x29, 0xe5, 0x3e, 0x10, 0xf7, 0xb1, 0x34, 0xe3, 0x68, 0x58, 0x41, 0x10, 0xca,
		0x9a, 0xdb, 0xfb, 0x37, 0xe0, 0x53, 0xe9, 0xdc, 0xb0, 0x8a, 0xe1, 0x47, 0xc5, 0xf9, 0xb5, 0xb0,
		0x36, 0xd4, 0x67, 0xfc, 0xb2, 0x10, 0x83, 0x77, 0x8e, 0x0b, 0x6d, 0x27, 0x38, 0xe9, 0xff, 0x0b,
		0xe4, 0xfd, 0x12, 0x66, 0x6f, 0xbf, 0x1b, 0x2c, 0xf4, 0xe5, 0xca, 0x6f, 0x37, 0x63, 0x45, 0xac,
		0xef, 0x72, 0xba, 0x14, 0x57, 0xa2, 0xa8, 0x53, 0x6a, 0x2c, 0x0f, 0xfc, 0x6b, 0x85, 0x74, 0x23,
		0x4f, 0x3c, 0x86, 0xcf, 0xc8, 0x10, 0xf9, 0x63, 0xf0, 0xf5, 0xb1, 0x5b, 0x4c, 0x27, 0x21, 0x48,
		0x48, 0xf4, 0x87, 0x11, 0x7f, 0x41, 0x84, 0x99, 0x4c, 0x13, 0x06, 0x96, 0xcd, 0x0c, 0x6a, 0x48,
		0x14, 0x63, 0xae, 0x76, 0x79, 0x7f, 0x0b, 0x76, 0x2e, 0x5e, 0xec, 0xca, 0xdd, 0x1e, 0xa9, 0xbf,
		0x6a, 0xfb, 0x9b, 0xdf, 0xbd, 0x70, 0x82, 0x1e, 0x79, 0x85, 0xc3, 0xf4, 0x18, 0x52, 0x30, 0x14,
		0x34, 0x03, 0xca, 0x31, 0x05, 0xb5, 0x45, 0xee, 0x3f, 0xb4, 0xc5, 0x70, 0xcd, 0xad, 0x71, 0xd9,
	}

	// Test data from herrjemand's verify.packed.webauthn.js (2019) at https://gist.github.com/herrjemand/dbeb2c2b76362052e5268224660b6fbc
	basicAttestationExpiredCertificate = `{
		"rawId": "wsLryOAxXMU54s2fCSWPzWjXHOBKPploN-UHftj4_rpIu6BZxNXppm82f7Y6iX9FEOKKeS5-N2TALeyzLnJfAA",
		"id":    "wsLryOAxXMU54s2fCSWPzWjXHOBKPploN-UHftj4_rpIu6BZxNXppm82f7Y6iX9FEOKKeS5-N2TALeyzLnJfAA",
		"response": {
			"attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAIzOihC6Ba80o5JnoYOJJ_EtEVmWQcAvxVCnsCFnVRQZAiAfeIddLPsPl1FeSX8B5xZANcQKGNoO7pb0TZPnuJdebGN4NWOBWQKzMIICrzCCAZegAwIBAgIESFs9tjANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZZdWJpY28gRklETyBQcmV2aWV3IENBMB4XDTE4MDQxMjEwNTcxMFoXDTE4MTIzMTEwNTcxMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTIxMzkzOTEyNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPss3TBDKMVySlDM5vYLrX0nqRtZ4eZvKXuJydQ9wrLHeIm08P-dAijLlG384BsZWJtngEqsl38oGJzNsyV0yiijbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS42MBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMvPkvVjXQiuvSZmGCB8NqTvGqhxyEfkoU-vz63PaaTsG3jEzjl0C7PZ26VxCvqWPJdM3P3e7Kp18sj4RjEHUmkya2PPipOwBd3p0qMQSQ8MeziCPLQ9uvGGb4YShcvaprMv4c21b4piza-znHneNCmmq-ZS4Y23o-vYv085_BEwyLPcmPjSZ5qWysCq7rVvZ7OWwcU1zu5RhSZyUKl8dzK9lAzs5OdRH2fzEewsW2OkB_Ow_jBvAxqwLXXTHuwMFaRfpmBoZuQlcofSrnwJ8KA-K-e0dKTz2zC8EbZrWYrSpbrHKyqxeBT6DkUd8H4tgAd5lOr_yqrtVmIaRfq07NmhhdXRoRGF0YVjElWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4_Xy7IpvdRBAAAAAPigEfOMCk0VgAYXER-e3H0AQMLC68jgMVzFOeLNnwklj81o1xzgSj6ZaDflB37Y-P66SLugWcTV6aZvNn-2Ool_RRDiinkufjdkwC3ssy5yXwClAQIDJiABIVggAYD1TSpf120DSVxen8ki56kF1bmT4EXO-P0JnSk5mMwiWCB3TlMZBRqPY6llzDcfHd-oW0EHdaFNgBdlGGFobpHKlw",
			"clientDataJSON":    "eyJjaGFsbGVuZ2UiOiJZTVdFVGYtUDc5aU1iLUJxZFRreVNOUmVPdmE3bksyaVZDOWZpQzhpR3ZZeXB1bkVPQ1pHWjYtWTVPVjFydk1pRGdBaldmRmk2VUMwV3lLR3NqQS1nQSIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4ub3JnIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
		},
		"type": "public-key"
	}`
)

type parseTest struct {
	name           string
	attestation    []byte
	wantAttStmtAlg x509.SignatureAlgorithm
	wantSig        []byte
	wantCredCert   *x509.Certificate
	wantCACerts    []*x509.Certificate
	wantECDAAKeyID []byte
}

type verifyTest struct {
	name          string
	attestation   []byte
	wantAttType   webauthn.AttestationType
	wantTrustPath interface{}
}

type verifyErrorTest struct {
	name         string
	attestation  []byte
	wantErrorMsg string
}

var parseTests = []parseTest{
	{
		"basic attestation 1",
		[]byte(basicAttestation1),
		x509.ECDSAWithSHA256,
		basicAttestation1Sig,
		parseCertificate(basicAttestation1CredCert),
		[]*x509.Certificate{parseCertificate(basicAttestation1CACert0), parseCertificate(basicAttestation1CACert1)},
		nil,
	},
	{
		"self attestation 1",
		[]byte(selfAttestation1),
		x509.SHA1WithRSA,
		selfAttestation1Sig,
		nil,
		nil,
		nil,
	},
}

var verifyTests = []verifyTest{
	{"basic attestation 1", []byte(basicAttestation1), webauthn.AttestationTypeBasic, []*x509.Certificate{parseCertificate(basicAttestation1CredCert), parseCertificate(basicAttestation1CACert0), parseCertificate(basicAttestation1CACert1)}},
	{"self attestation 1", []byte(selfAttestation1), webauthn.AttestationTypeSelf, nil},
}

var verifyErrorTests = []verifyErrorTest{
	{"expired certificate", []byte(basicAttestationExpiredCertificate), "certificate has expired"},
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

func TestParsePackedAttestation(t *testing.T) {
	for _, tc := range parseTests {
		t.Run(tc.name, func(t *testing.T) {
			var credentialAttestation webauthn.PublicKeyCredentialAttestation
			if err := json.Unmarshal(tc.attestation, &credentialAttestation); err != nil {
				t.Fatalf("failed to unmarshal attestation %s: %q", string(tc.attestation), err)
			}
			attStmt, ok := credentialAttestation.AttStmt.(*packedAttestationStatement)
			if !ok {
				t.Fatalf("attestation type %T, want *packedAttestationStatement", credentialAttestation.AttStmt)
			}
			if attStmt.Algorithm != tc.wantAttStmtAlg {
				t.Errorf("attestation alg %s, want %s", attStmt.Algorithm, tc.wantAttStmtAlg)
			}
			if !bytes.Equal(attStmt.sig, tc.wantSig) {
				t.Errorf("attestation sig %v, want %v", attStmt.sig, tc.wantSig)
			}
			if !certificateEqual(attStmt.attestnCert, tc.wantCredCert) {
				t.Errorf("attestation cred cert %v, want %v", attStmt.attestnCert, tc.wantCredCert)
			}
			if len(attStmt.caCerts) != len(tc.wantCACerts) {
				t.Errorf("attestation has %d ca certificates, want %d", len(attStmt.caCerts), len(tc.wantCACerts))
			} else {
				for i, c := range attStmt.caCerts {
					if !bytes.Equal(c.Raw, tc.wantCACerts[i].Raw) {
						t.Errorf("attestation ca cert %d %v, want %v", i, c, tc.wantCACerts[i])
					}
				}
			}
			if !reflect.DeepEqual(attStmt.ecdaaKeyID, tc.wantECDAAKeyID) {
				t.Errorf("attestation ecdaaKeyID %v, want %v", attStmt.ecdaaKeyID, tc.wantECDAAKeyID)
			}
		})
	}
}

func TestVerifyPackedAttestation(t *testing.T) {
	for _, tc := range verifyTests {
		t.Run(tc.name, func(t *testing.T) {
			var credentialAttestation webauthn.PublicKeyCredentialAttestation
			if err := json.Unmarshal(tc.attestation, &credentialAttestation); err != nil {
				t.Fatalf("failed to unmarshal attestation %s: %q", string(tc.attestation), err)
			}
			attType, trustPath, err := credentialAttestation.VerifyAttestationStatement()
			if err != nil {
				t.Fatalf("Verify() returns error %q", err)
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

func TestVerifyPackedAttestationError(t *testing.T) {
	for _, tc := range verifyErrorTests {
		t.Run(tc.name, func(t *testing.T) {
			var credentialAttestation webauthn.PublicKeyCredentialAttestation
			if err := json.Unmarshal(tc.attestation, &credentialAttestation); err != nil {
				t.Fatalf("failed to unmarshal attestation %s: %q", string(tc.attestation), err)
			}
			if _, _, err := credentialAttestation.VerifyAttestationStatement(); err == nil {
				t.Errorf("VerifyAttestationStatement() returns no error, want error containing substring %q", tc.wantErrorMsg)
			} else if !strings.Contains(err.Error(), tc.wantErrorMsg) {
				t.Errorf("VerifyAttestationStatement() returns error %q,  want error containing substring %q", err, tc.wantErrorMsg)
			}
		})
	}
}
