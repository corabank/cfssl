package newcert

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/bundler"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/cloudflare/cfssl/signer"
	stdocsp "golang.org/x/crypto/ocsp"
)

const (
	// CSRNoHostMessage is used to alert the user to a certificate lacking a hosts field.
	CSRNoHostMessage = `This certificate lacks a "hosts" field. This makes it unsuitable for
websites. For more information see the Baseline Requirements for the Issuance and Management
of Publicly-Trusted Certificates, v.1.1.6, from the CA/Browser Forum (https://cabforum.org);
specifically, section 10.2.3 ("Information Requirements").`
)

// Validator is a type of function that contains the logic for validating
// a certificate request.
type Validator func(*csr.CertificateRequest) error

type newCertRequest struct {
	Request *csr.CertificateRequest `json:"request"`
	Profile string                  `json:"profile"`
	Label   string                  `json:"label"`
	Bundle  bool                    `json:"bundle"`
}

// Sum contains digests for a certificate or certificate request.
type Sum struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha-1"`
	SHA256 string `json:"sha-256"`
}

type options struct {
	ocspSigner    ocsp.Signer
	caBundleFile  string
	intBundleFile string
}

// Opt is a functional option for configuring a new Handler.
type Opt func(*options)

// WithOCSPSigner sets the OCSP signer for the Handler.
func WithOCSPSigner(signer ocsp.Signer) Opt {
	return func(o *options) {
		o.ocspSigner = signer
	}
}

// WithBundler sets the CA and intermediate bundle files for the Handler.
func WithBundler(caBundleFile, intBundleFile string) Opt {
	return func(o *options) {
		o.caBundleFile = caBundleFile
		o.intBundleFile = intBundleFile
	}
}

// Handler accepts JSON-encoded certificate requests and returns
// a new private key and signed certificate; it handles sending
// the CSR to the server and create an OCSP response for the certificate.
type Handler struct {
	csrGen     *csr.Generator
	bundler    *bundler.Bundler
	signer     signer.Signer
	ocspSigner ocsp.Signer
}

// NewHandler creates a new Handler for generating certificates directly
// from certificate requests.
func NewHandler(validator Validator, signer signer.Signer, opts ...Opt) (http.Handler, error) {
	hdl := &Handler{
		csrGen: &csr.Generator{Validator: validator},
		signer: signer,
	}

	options := options{}
	for _, opt := range opts {
		opt(&options)
	}

	bundler, err := bundler.NewBundler(options.caBundleFile, options.intBundleFile)
	if err != nil {
		return nil, err
	}

	hdl.bundler = bundler
	hdl.ocspSigner = options.ocspSigner

	return api.HTTPHandler{
		Handler: hdl,
		Methods: []string{"POST"},
	}, nil
}

// Handle handles HTTP requests to generate certificates.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Info("request for csr (with ocsp support)")

	newCert := newCertRequest{}
	newCert.Request = csr.New()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Warningf("failed to read request body: %v", err)
		return errors.NewBadRequest(err)
	}

	err = json.Unmarshal(body, &newCert)
	if err != nil {
		log.Warningf("failed to unmarshal request: %v", err)
		return errors.NewBadRequest(err)
	}

	if newCert.Request == nil {
		log.Warning("empty request received")
		return errors.NewBadRequestString("missing request section")
	}

	if newCert.Request.CA != nil {
		log.Warningf("request received with CA section")
		return errors.NewBadRequestString("ca section only permitted in initca")
	}

	csr, key, err := h.csrGen.ProcessRequest(newCert.Request)
	if err != nil {
		log.Warningf("failed to process CSR: %v", err)
		// The validator returns a *cfssl/errors.HttpError
		return err
	}

	signReq := signer.SignRequest{
		Request: string(csr),
		Profile: newCert.Profile,
		Label:   newCert.Label,
	}

	certBytes, err := h.signer.Sign(signReq)
	if err != nil {
		log.Warningf("failed to sign request: %v", err)
		return err
	}

	reqSum, err := computeSum(csr)
	if err != nil {
		return errors.NewBadRequest(err)
	}

	certSum, err := computeSum(certBytes)
	if err != nil {
		return errors.NewBadRequest(err)
	}

	bundle, err := h.bundler.BundleFromPEMorDER(certBytes, nil, bundler.Optimal, "")
	if err != nil {
		return err
	}

	if bundle == nil {
		log.Critical("failed to bundle certificate")
		return fmt.Errorf("failed to bundle certificate")
	}

	if h.ocspSigner != nil {
		ocspReq := ocsp.SignRequest{
			Certificate: bundle.Cert,
			Status:      "good",
		}

		ocspResponse, err := h.ocspSigner.Sign(ocspReq)
		if err != nil {
			log.Critical("Unable to sign OCSP response: ", err)
			return err
		}

		// We parse the OCSP response in order to get the next
		// update time/expiry time
		ocspParsed, err := stdocsp.ParseResponse(ocspResponse, nil)
		if err != nil {
			return err
		}

		ocspRecord := certdb.OCSPRecord{
			Serial: bundle.Cert.SerialNumber.String(),
			AKI:    hex.EncodeToString(bundle.Cert.AuthorityKeyId),
			Body:   string(ocspResponse),
			Expiry: ocspParsed.NextUpdate,
		}

		dbAccessor := h.signer.GetDBAccessor()
		if err := dbAccessor.InsertOCSP(ocspRecord); err != nil {
			log.Critical("Unable to insert OCSP response: ", err)
			return err
		}
	}

	result := map[string]interface{}{
		"private_key":         string(key),
		"certificate_request": string(csr),
		"certificate":         string(certBytes),
		"serial_number":       bundle.Cert.SerialNumber.String(),
		"expiration":          bundle.Expires.Unix(),
		"sums": map[string]Sum{
			"certificate_request": reqSum,
			"certificate":         certSum,
		},
	}

	if len(newCert.Request.Hosts) == 0 {
		return api.SendResponseWithMessage(w, result, CSRNoHostMessage,
			errors.New(errors.PolicyError, errors.InvalidRequest).ErrorCode)
	}

	return api.SendResponse(w, result)
}

func computeSum(in []byte) (sum Sum, err error) {
	var data []byte
	p, _ := pem.Decode(in)
	if p == nil {
		err = errors.NewBadRequestString("not a CSR or certificate")
		return
	}

	switch p.Type {
	case "CERTIFICATE REQUEST":
		var req *x509.CertificateRequest
		req, err = x509.ParseCertificateRequest(p.Bytes)
		if err != nil {
			return
		}
		data = req.Raw
	case "CERTIFICATE":
		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(p.Bytes)
		if err != nil {
			return
		}
		data = cert.Raw
	default:
		err = errors.NewBadRequestString("not a CSR or certificate")
		return
	}

	md5Sum := md5.Sum(data)
	sha1Sum := sha1.Sum(data)
	sha256Sum := sha256.Sum256(data)
	sum.MD5 = fmt.Sprintf("%X", md5Sum[:])
	sum.SHA1 = fmt.Sprintf("%X", sha1Sum[:])
	sum.SHA256 = fmt.Sprintf("%X", sha256Sum[:])
	return
}
