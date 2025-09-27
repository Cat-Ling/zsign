package signer

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blacktop/go-macho"
	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"
)

// ProvisioningProfile represents the data parsed from a .mobileprovision file.
type ProvisioningProfile struct {
	Name           string       `plist:"Name"`
	Entitlements   Entitlements `plist:"Entitlements"`
	DeveloperCerts [][]byte     `plist:"DeveloperCertificates"`
}

// InfoPlist represents the data parsed from an Info.plist file.
type InfoPlist struct {
	BundleExecutable string `plist:"CFBundleExecutable"`
}

// Entitlements represents the entitlements from a provisioning profile.
type Entitlements map[string]interface{}

// p7SignedData is a simplified struct for parsing PKCS#7 signed data.
type p7SignedData struct {
	ContentType asn1.ObjectIdentifier
	Content     struct {
		Data asn1.RawValue `asn1:"tag:0,explicit"`
	} `asn1:"tag:0,explicit"`
}

// CodeResources represents the structure of the CodeResources plist file.
type CodeResources struct {
	Files  map[string]string `plist:"files"`
	Files2 map[string]string `plist:"files2"`
}

// Signer is responsible for signing application bundles.
type Signer struct {
}

// NewSigner creates a new Signer.
func NewSigner() *Signer {
	return &Signer{}
}

// Sign takes the paths to the necessary files and performs the signing operation.
func (s *Signer) Sign(ipaPath, p12Path, provisionPath, password, outputDir string) (string, error) {
	unzipDir := filepath.Join(outputDir, "unzipped")
	if err := os.MkdirAll(unzipDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create unzip directory: %w", err)
	}
	if err := unzip(ipaPath, unzipDir); err != nil {
		return "", fmt.Errorf("failed to unzip IPA: %w", err)
	}

	payloadDir := filepath.Join(unzipDir, "Payload")
	files, err := os.ReadDir(payloadDir)
	if err != nil {
		return "", fmt.Errorf("failed to read Payload directory: %w", err)
	}

	var appBundlePath string
	for _, file := range files {
		if file.IsDir() && strings.HasSuffix(file.Name(), ".app") {
			appBundlePath = filepath.Join(payloadDir, file.Name())
			break
		}
	}
	if appBundlePath == "" {
		return "", errors.New("failed to find .app bundle in Payload")
	}

	infoPlistPath := filepath.Join(appBundlePath, "Info.plist")
	infoPlistFile, err := os.Open(infoPlistPath)
	if err != nil {
		return "", fmt.Errorf("failed to open Info.plist: %w", err)
	}
	defer infoPlistFile.Close()

	var infoPlist InfoPlist
	decoder := plist.NewDecoder(infoPlistFile)
	if err := decoder.Decode(&infoPlist); err != nil {
		return "", fmt.Errorf("failed to decode Info.plist: %w", err)
	}
	executablePath := filepath.Join(appBundlePath, infoPlist.BundleExecutable)

	m, err := macho.Open(executablePath)
	if err != nil {
		return "", fmt.Errorf("failed to open executable: %w", err)
	}
	defer m.Close()

	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		return "", fmt.Errorf("failed to read .p12 file: %w", err)
	}
	privateKey, cert, chain, err := s.ParseP12(p12Data, password)
	if err != nil {
		return "", fmt.Errorf("failed to parse .p12 file: %w", err)
	}

	provisionData, err := os.ReadFile(provisionPath)
	if err != nil {
		return "", fmt.Errorf("failed to read .mobileprovision file: %w", err)
	}
	profile, _, err := s.ParseProvisioningProfile(provisionData)
	if err != nil {
		return "", fmt.Errorf("failed to parse .mobileprovision file: %w", err)
	}

	// Create the signature
	sig, err := createSignature(m, profile.Entitlements, privateKey, cert, chain)
	if err != nil {
		return "", fmt.Errorf("failed to create signature: %w", err)
	}

	// Embed the signature
	if err := m.Sign(sig); err != nil {
		return "", fmt.Errorf("failed to embed signature: %w", err)
	}

	// Re-zip the bundle
	signedIPAPath := filepath.Join(outputDir, "signed.ipa")
	if err := zipit(unzipDir, signedIPAPath); err != nil {
		return "", fmt.Errorf("failed to re-zip signed bundle: %w", err)
	}

	return signedIPAPath, nil
}

func createSignature(m *macho.File, entitlements Entitlements, pkey crypto.PrivateKey, cert *x509.Certificate, chain []*x509.Certificate) ([]byte, error) {
	// Create Code Directory
	cd, err := m.CodeSignature()
	if err != nil {
		return nil, err
	}

	// Create Entitlements
	entitlementsData, err := plist.Marshal(entitlements, plist.XMLFormat)
	if err != nil {
		return nil, err
	}

	// Create PKCS#7 signature
	signedData, err := newSignedData(cd.CodeDirectories[0].Hash, entitlementsData)
	if err != nil {
		return nil, err
	}

	return signedData.Sign(cert, chain, pkey)
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier
	ContentInfo      contentInfo
	Certificates     []asn1.RawValue `asn1:"tag:0,optional"`
	SignerInfos      []signerInfo
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type signerInfo struct {
	Version                   int
	IssuerAndSerialNumber     issuerAndSerialNumber
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"tag:0,optional"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type issuerAndSerialNumber struct {
	Issuer
	SerialNumber *asn1.RawValue
}

type Issuer struct {
	CommonName         string `asn1:"commonName,optional"`
	Country            string `asn1:"countryName,optional"`
	Organization       string `asn1:"organizationName,optional"`
	OrganizationalUnit string `asn1:"organizationalUnitName,optional"`
}

func newSignedData(cdHash []byte, entitlementsData []byte) (*signedData, error) {
	// OIDs
	var (
		oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
		oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
		oidContentType            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
		oidMessageDigest          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
		oidAppleDeveloper         = asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 1}
		oidAppleEntitlements      = asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}
	)

	// Create content
	content, err := asn1.Marshal(cdHash)
	if err != nil {
		return nil, err
	}

	// Create authenticated attributes
	contentType, err := asn1.Marshal(oidData)
	if err != nil {
		return nil, err
	}
	messageDigest, err := asn1.Marshal(cdHash)
	if err != nil {
		return nil, err
	}
	appleEntitlements, err := asn1.Marshal(entitlementsData)
	if err != nil {
		return nil, err
	}

	authAttrs := []attribute{
		{Type: oidContentType, Value: asn1.RawValue{FullBytes: contentType}},
		{Type: oidMessageDigest, Value: asn1.RawValue{FullBytes: messageDigest}},
		{Type: oidAppleDeveloper, Value: asn1.RawValue{FullBytes: []byte{}}},
		{Type: oidAppleEntitlements, Value: asn1.RawValue{FullBytes: appleEntitlements}},
	}
	authAttrsBytes, err := asn1.Marshal(authAttrs)
	if err != nil {
		return nil, err
	}

	// Create signer info
	h := sha256.Sum256(authAttrsBytes)
	signerInfo := signerInfo{
		Version: 1,
		DigestAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, // sha256
		},
		AuthenticatedAttributes: authAttrs,
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, // rsaEncryption
		},
		EncryptedDigest: h[:],
	}

	// Create signed data
	return &signedData{
		Version: 1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}, // sha256
		},
		ContentInfo: contentInfo{
			ContentType: oidSignedData,
			Content:     asn1.RawValue{FullBytes: content},
		},
		SignerInfos: []signerInfo{signerInfo},
	}, nil
}

func (sd *signedData) Sign(cert *x509.Certificate, chain []*x509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
	sd.Certificates = make([]asn1.RawValue, len(chain)+1)
	sd.Certificates[0] = asn1.RawValue{FullBytes: cert.Raw}
	for i, c := range chain {
		sd.Certificates[i+1] = asn1.RawValue{FullBytes: c.Raw}
	}

	// Sign
	rsaKey, ok := pkey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an RSA key")
	}

	h := sha256.Sum256(sd.SignerInfos[0].AuthenticatedAttributes[0].Value.FullBytes)
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h[:])
	if err != nil {
		return nil, err
	}
	sd.SignerInfos[0].EncryptedDigest = sig

	return asn1.Marshal(*sd)
}
// unzip extracts a zip archive to a destination directory.
func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		_, err = io.Copy(outFile, rc)

		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}

func zipit(source, target string) error {
	zipfile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer zipfile.Close()

	archive := zip.NewWriter(zipfile)
	defer archive.Close()

	info, err := os.Stat(source)
	if err != nil {
		return nil
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}

	filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		if baseDir != "" {
			header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
		}

		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(writer, file)
		return err
	})

	return err
}

// ParseProvisioningProfile parses a .mobileprovision file.
func (s *Signer) ParseProvisioningProfile(data []byte) (*ProvisioningProfile, []*x509.Certificate, error) {
	var p7 p7SignedData
	if _, err := asn1.Unmarshal(data, &p7); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal ASN.1 data: %w", err)
	}

	plistData := p7.Content.Data.Bytes
	if len(plistData) == 0 {
		return nil, nil, errors.New("plist data not found in provisioning profile")
	}

	var profile ProvisioningProfile
	if _, err := plist.Unmarshal(plistData, &profile); err != nil {
		return nil, nil, fmt.Errorf("failed to decode plist: %w", err)
	}

	var parsedCerts []*x509.Certificate
	for _, certData := range profile.DeveloperCerts {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			continue
		}
		parsedCerts = append(parsedCerts, cert)
	}

	return &profile, parsedCerts, nil
}

// ParseP12 takes the content of a .p12 file and its password and returns the private key and certificate.
func (s *Signer) ParseP12(p12Data []byte, password string) (crypto.PrivateKey, *x509.Certificate, []*x509.Certificate, error) {
	return pkcs12.DecodeChain(p12Data, password)
}

// GenerateCodeResources walks the app bundle, calculates hashes, and returns the CodeResources data.
func (s *Signer) GenerateCodeResources(appPath string) (*CodeResources, error) {
	resources := &CodeResources{
		Files:  make(map[string]string),
		Files2: make(map[string]string),
	}

	err := filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(appPath, path)
		if err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		h := sha1.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		resources.Files[relPath] = hex.EncodeToString(h.Sum(nil))
		resources.Files2[relPath] = resources.Files[relPath]

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk app bundle: %w", err)
	}

	return resources, nil
}