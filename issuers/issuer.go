package issuers

import (
	"context"
	"encoding/pem"
	"fmt"
	"time"

	//cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	//cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	//metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/chojnack/adcs-issuer/adcs"
	api "github.com/chojnack/adcs-issuer/api/v1"
	"github.com/fullsailor/pkcs7"
)

type Issuer struct {
	client.Client
	certServ            adcs.AdcsCertsrv
	RetryInterval       time.Duration
	StatusCheckInterval time.Duration
	AdcsTemplateName    string
}

// Go to ADCS for a certificate. If current status is 'Pending' then
// check for existing request. Otherwise ask for new.
// The current status is set in the passed request.
// If status is 'Ready' the returns include certificate and CA cert respectively.
func (i *Issuer) Issue(ctx context.Context, ar *api.AdcsRequest) ([]byte, []byte, error) {
	var adcsResponseStatus adcs.AdcsResponseStatus
	var desc string
	var id string
	var err error
	if ar.Status.State != api.Unknown {
		// Of all the statuses only Pending requires processing.
		// All others are final
		if ar.Status.State == api.Pending {
			// Check the status of the request on the ADCS
			if ar.Status.Id == "" {
				return nil, nil, fmt.Errorf("ADCS ID not set.")
			}
			adcsResponseStatus, desc, id, err = i.certServ.GetExistingCertificate(ar.Status.Id)
		} else {
			// Nothing to do
			return nil, nil, nil
		}
	} else {
		// New request
		adcsResponseStatus, desc, id, err = i.certServ.RequestCertificate(string(ar.Spec.CSRPEM), i.AdcsTemplateName)
		// klog.Info("hello from requestCertificate function!")
	}
	if err != nil {
		// This is a local error
		return nil, nil, err
	}

	var cert []byte
	switch adcsResponseStatus {
	case adcs.Pending:
		// It must be checked again later
		ar.Status.State = api.Pending
		ar.Status.Id = id
		ar.Status.Reason = desc
	case adcs.Ready:
		// Certificate obtained successfully
		ar.Status.State = api.Ready
		ar.Status.Id = id
		ar.Status.Reason = ""
		cert = []byte(desc)
	case adcs.Rejected:
		// Certificate request rejected by ADCS
		ar.Status.State = api.Rejected
		ar.Status.Id = id
		ar.Status.Reason = desc
	case adcs.Errored:
		// Unknown problem occured on ADCS
		ar.Status.State = api.Errored
		ar.Status.Id = id
		ar.Status.Reason = desc
	}

	caPKCS7, err := i.certServ.GetCaCertificateChain()
	if err != nil {
		return nil, nil, err
	}

	ca, err := parseCaCert([]byte(caPKCS7))
	if err != nil {
		klog.Error("something went wrong with parsing CA-cert PKCS7 to PEM")
		return nil, nil, err
	}

	klog.V(4).Infof("will return cert! inside issuer.go: %v", cert)
	return cert, ca, nil

}

// implementation converting PKCS7 to PEM format
func parseCaCert(caPKCS7 []byte) (caPem []byte, err error) {

	block, _ := pem.Decode([]byte(caPKCS7))
	p7, err := pkcs7.Parse(block.Bytes)

	caPem = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: p7.Certificates[0].Raw,
	})

	return caPem, err
}
