package issuers

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TODO: provide proper PKCS7 certificates for testing.
// TODO: create makefile to populate testdata (openssl)
// 2 tests will fail!
// testdata/pkcs7.pem and testdata/x509.pem aren't provided, for the tests to be able to run, please provide own certs of these format.

func TestParsingCaCertShouldReturnX509(t *testing.T) {
	// arrange
	pkcs7Pem, err := ioutil.ReadFile("testdata/pkcs7.pem")
	assert.NoError(t, err)

	validX509Certificate, err := ioutil.ReadFile("testdata/x509.pem")
	assert.NoError(t, err)
	// act
	parsedCaCert, err := parseCaCert(pkcs7Pem)

	// assert
	assert.NoError(t, err)
	assert.Equal(t, validX509Certificate, parsedCaCert)
}

func TestIncorrectFormatPkcs(t *testing.T) {
	//arrange
	incorrectPKCS7Cert, err := ioutil.ReadFile("testdata/incorrectPKCS7Cert.pem")
	assert.NoError(t, err)

	// act
	ca, err := parseCaCert(incorrectPKCS7Cert)

	// assert
	assert.EqualError(t, err, "parsing PKCS7: ber2der: BER tag length is more than available data")
	assert.Nil(t, ca, "expecting ca to be empty")
}

func TestEmptyPkcs(t *testing.T) {
	// arrange
	emptyPKCS7 := []byte(``)

	// act
	ca, err := parseCaCert(emptyPKCS7)

	// assert
	assert.EqualError(t, err, "error decoding the pem block")
	assert.Nil(t, ca, "expecting ca to be empty")
}

func TestIncorrectCertFormat(t *testing.T) {
	// arrange
	incorrectCertFormat := []byte(`This is not correct!`)

	// act
	ca, err := parseCaCert(incorrectCertFormat)

	// assert
	assert.Error(t, err)
	assert.EqualError(t, err, "error decoding the pem block")
	assert.Nil(t, ca, "expecting ca to be empty ")
}

func TestParseCaCertCorrectPKCS7(t *testing.T) {
	// arrange
	// raw format pkcs7.p7b from cfss testdata (https://github.com/cloudflare/cfssl/tree/master/helpers/testdata)
	rawPkcs7, err := ioutil.ReadFile("testdata/cfss_rawPKCS7.p7b")
	assert.NoError(t, err)
	cfssOutputX509, err := ioutil.ReadFile("testdata/cfss_outputx509.pem")
	assert.NoError(t, err)

	// act
	ca, err := parseCaCert(rawPkcs7)

	// assert
	assert.NoError(t, err)
	assert.Equal(t, cfssOutputX509, ca)
}

func TestCorrectX509Cert(t *testing.T) {
	// arrange
	// raw format pkcs7.p7b from cfss testdata (https://github.com/cloudflare/cfssl/tree/master/helpers/testdata)
	x509, err := ioutil.ReadFile("testdata/x509.pem")

	// act
	parsedCaCert, err := parseCaCert(x509)

	// assert
	assert.NoError(t, err)
	assert.Equal(t, x509, parsedCaCert)
}
