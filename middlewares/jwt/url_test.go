package jwt

import (
	"testing"
	"net/url"
	"fmt"
	traefiktls "github.com/containous/traefik/tls"
	"runtime"
	"path"
	"os"
)

func TestAddHashAndRemoveHashUsingClientSecretSuccess(t *testing.T) {
	testUrl, err := url.Parse("https://127.0.0.1/test/do.aspx?param1=value1&param2=value2&param3=value3")
	if err != nil {
		panic(err)
	}

	key := []byte("mySecret")

	err = addMacHashToUrl(testUrl, key)
	if err != nil {
		panic(err)
	}

	err = verifyAndStripMacHashFromUrl(testUrl, key)
	if err != nil {
		panic(err)
	}
}

func getPrivateKeyForTest(relativePathToCert string) (interface{}, error){
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), relativePathToCert)

	publicKeyPath := fmt.Sprintf("%s.crt", certPath)
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		publicKeyPath = fmt.Sprintf("%s.cert", certPath)
	}

	privateKeyPath := fmt.Sprintf("%s.key", certPath)

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(publicKeyPath),
		KeyFile:  traefiktls.FileOrContent(privateKeyPath),
	}

	if !certificate.CertFile.IsPath() {
		return nil, fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile))
	}

	if !certificate.KeyFile.IsPath() {
		return nil, fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile))
	}

	privateKeyPemData, err := certificate.KeyFile.Read()
	if err != nil {
		return nil, err
	}

	privateKey, err := GetPrivateKeyFromPem(privateKeyPemData)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func getPublicKeyForTest(relativePathToCert string) (interface{}, error){
	_, filename, _, _ := runtime.Caller(0)
	certPath := path.Join(path.Dir(filename), relativePathToCert)

	publicKeyPath := fmt.Sprintf("%s.crt", certPath)
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		publicKeyPath = fmt.Sprintf("%s.cert", certPath)
	}

	privateKeyPath := fmt.Sprintf("%s.key", certPath)

	certificate := &traefiktls.Certificate{
		CertFile: traefiktls.FileOrContent(publicKeyPath),
		KeyFile:  traefiktls.FileOrContent(privateKeyPath),
	}

	if !certificate.CertFile.IsPath() {
		return nil, fmt.Errorf("CertFile path is invalid: %s", string(certificate.CertFile))
	}

	if !certificate.KeyFile.IsPath() {
		return nil, fmt.Errorf("KeyFile path is invalid: %s", string(certificate.KeyFile))
	}

	publicKeyPemData, err := certificate.CertFile.Read()
	if err != nil {
		return nil, err
	}

	publicKey, _, err := GetPublicKeyFromPem(publicKeyPemData)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func TestAddHashAndRemoveHashUsingPrivateKeyAndPublicKeySuccess(t *testing.T) {
	testUrl, err := url.Parse("https://127.0.0.1/test/do.aspx?param1=value1&param2=value2&param3=value3")
	if err != nil {
		panic(err)
	}

	privateKey, err := getPrivateKeyForTest("../../integration/fixtures/https/snitest.com")
	err = addMacHashToUrl(testUrl, privateKey)
	if err != nil {
		panic(err)
	}

	publicKey, err := getPublicKeyForTest("../../integration/fixtures/https/snitest.com")

	err = verifyAndStripMacHashFromUrl(testUrl, publicKey)
	if err != nil {
		panic(err)
	}
}

func TestAddHashAndRemoveHashUsingPrivateKeyOnlySuccess(t *testing.T) {
	testUrl, err := url.Parse("https://127.0.0.1/test/do.aspx?param1=value1&param2=value2&param3=value3")
	if err != nil {
		panic(err)
	}

	privateKey, err := getPrivateKeyForTest("../../integration/fixtures/https/snitest.com")
	err = addMacHashToUrl(testUrl, privateKey)
	if err != nil {
		panic(err)
	}
	err = verifyAndStripMacHashFromUrl(testUrl, privateKey)
	if err != nil {
		panic(err)
	}
}
