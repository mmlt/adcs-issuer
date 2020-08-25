package adcs

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	neturl "net/url"
	"regexp"
	"strings"

	"github.com/Azure/go-ntlmssp"
	"k8s.io/klog"
)

type NtlmCertsrv struct {
	url        string
	username   string
	password   string
	ca         string
	httpClient *http.Client
}

const (
	certnew_cer = "certnew.cer"
	certnew_p7b = "certnew.p7b"
	certcarc    = "certcarc.asp"
	certfnsh    = "certfnsh.asp"

	ct_pkix   = "application/pkix-cert"
	ct_pkcs7  = "application/x-pkcs7-certificates"
	ct_html   = "text/html"
	ct_urlenc = "application/x-www-form-urlencoded"
)

func NewNtlmCertsrv(url string, username string, password string, caCertPool *x509.CertPool, verify bool) (AdcsCertsrv, error) {
	var client *http.Client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //TODO make false,
			RootCAs:            caCertPool,
		},
	}

	if username != "" && password != "" {
		// Set up NTLM authentication
		client = &http.Client{
			Transport: ntlmssp.Negotiator{
				RoundTripper: transport,
			},
		}
	} else {
		// Plain client with no NTLM
		client = &http.Client{
			Transport: transport,
		}
		klog.Warningf("Not using NTLM")
	}

	c := &NtlmCertsrv{
		url:        url,
		username:   username,
		password:   password,
		httpClient: client,
	}
	if verify {
		success, err := c.verifyNtlm()
		if !success {
			return nil, err
		}
	}
	return c, nil
}

// Check if NTLM authentication is working for current credentials and URL
func (s *NtlmCertsrv) verifyNtlm() (bool, error) {
	klog.Infof("NTLM verification for user %s in URL %s", s.username, s.url)
	req, _ := http.NewRequest("GET", s.url, nil)
	req.SetBasicAuth(s.username, s.password)
	res, err := s.httpClient.Do(req)
	if err != nil {
		klog.Errorf("ADCS server error: %s", err.Error())
		return false, err
	}
	klog.Infof("NTLM verification successful (res = %s)", res.Status)
	return true, nil
}

/*
 * Returns:
 * - Certificate response status
 * - Certificate (if status is Ready) or status description (if status is not Ready)
 * - ADCS Request ID
 * - Error
 */
func (s *NtlmCertsrv) GetExistingCertificate(id string) (AdcsResponseStatus, string, string, error) {
	var certStatus AdcsResponseStatus = Unknown

	url := fmt.Sprintf("%s/%s?ReqID=%s&ENC=b64", s.url, certnew_cer, id)
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(s.username, s.password)
	req.Header.Set("User-agent", "Mozilla")
	res, err := s.httpClient.Do(req)
	if err != nil {
		klog.Errorf("ADCS Certserv error: %s", err.Error())
		return certStatus, "", id, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		switch ct := strings.Split(res.Header.Get(http.CanonicalHeaderKey("content-type")), ";"); ct[0] {
		case ct_html:
			// Denied or pending
			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				klog.Errorf("Cannot read ADCS Certserv response: %s", err.Error())
				return certStatus, "", id, err
			}
			bodyString := string(body)
			dispositionMessage := "unknown"
			exp := regexp.MustCompile(`Disposition message:[^\t]+\t\t([^\r\n]+)`)
			found := exp.FindStringSubmatch(bodyString)
			if len(found) > 1 {
				dispositionMessage = found[1]
				expPending := regexp.MustCompile(`.*Taken Under Submission*.`)
				expRejected := regexp.MustCompile(`.*Denied by*.`)
				switch true {
				case expPending.MatchString(bodyString):
					certStatus = Pending
				case expRejected.MatchString(bodyString):
					certStatus = Rejected
				default:
					certStatus = Errored
				}

			} else {
				// If the response page is not formatted as we expect it
				// we just log the entire page
				disp := bodyString
				if len(found) == 1 {
					// Or at least the 'Disposition message' section
					disp = found[0]
				}
				err = fmt.Errorf("Disposition message unknown: %s", disp)
				klog.Errorf(err.Error())
			}

			lastStatusMessage := ""
			exp = regexp.MustCompile(`LastStatus:[^\t]+\t\t([^\r\n]+)`)
			found = exp.FindStringSubmatch(bodyString)
			if len(found) > 1 {
				lastStatusMessage = " " + found[1]
			} else {
				klog.Warningf("Last status unknown.")
			}
			return certStatus, dispositionMessage + lastStatusMessage, id, err

		case ct_pkix:
			// Certificate
			cert, err := ioutil.ReadAll(res.Body)
			if err != nil {
				klog.Errorf("Cannot read ADCS Certserv response: %s", err.Error())
				return certStatus, "", id, err
			}
			return Ready, string(cert), id, nil
		default:
			err = fmt.Errorf("Unexpected content type %s:", ct)
			klog.Errorf(err.Error())
			return certStatus, "", id, err
		}
	}
	return certStatus, "", id, fmt.Errorf("ADCS Certsrv response status %s. Error: %s", res.Status, err.Error())

}

/*
 * Returns:
 * - Certificate response status
 * - Certificate (if status is Ready) or status description (if status is not Ready)
 * - ADCS Request ID (if known)
 * - Error
 */
func (s *NtlmCertsrv) RequestCertificate(csr string, template string) (AdcsResponseStatus, string, string, error) {
	var certStatus AdcsResponseStatus = Unknown

	url := fmt.Sprintf("%s/%s", s.url, certfnsh)
	params := neturl.Values{
		"Mode":                {"newreq"},
		"CertRequest":         {csr},
		"CertAttrib":          {"CertificateTemplate:" + template},
		"FriendlyType":        {"Saved-Request Certificate"},
		"TargetStoreFlags":    {"0"},
		"SaveCert":            {"yes"},
		"CertificateTemplate": {template},
	}

	req, err := http.NewRequest("POST", url, bytes.NewBufferString(params.Encode()))
	if err != nil {
		klog.Errorf("Cannot create request: %s", err.Error())
		return certStatus, "", "", err
	}
	req.SetBasicAuth(s.username, s.password)
	klog.V(5).Infof("Username as BasicAuth: \n %v ", s.username)

	req.Header.Set("User-agent", "Mozilla")
	req.Header.Set("Content-type", ct_urlenc)

	// klog.V(4).Infof("Sending [raw] request:\n %v\n", req)

	res, err := s.httpClient.Do(req)
	// klog.V(4).Infof("Response:\n %v\n", res)
	if err != nil {
		klog.Errorf("ADCS Certserv error: %s", err.Error())
		return certStatus, "", "", err
	}

	body, err := ioutil.ReadAll(res.Body)
	if res.Header.Get("Content-type") == ct_pkix {
		// klog.V(4).Infof("klog_v4: returned [Ready] %v", Ready)
		return Ready, string(body), "none", nil
	}
	if err != nil {
		klog.Errorf("Cannot read ADCS Certserv response: %s", err.Error())
		return certStatus, "", "", err
	}

	bodyString := string(body)

	// klog.V(5).Infof("Body:\n%s", bodyString)

	exp := regexp.MustCompile(`certnew.cer\?ReqID=([0-9]+)&`)
	found := exp.FindStringSubmatch(bodyString)
	certId := ""
	if len(found) > 1 {
		certId = found[1]
	} else {
		exp = regexp.MustCompile(`Your Request Id is ([0-9]+).`)
		found = exp.FindStringSubmatch(bodyString)
		if len(found) > 1 {
			certId = found[1]
		} else {
			errorString := ""
			exp = regexp.MustCompile(`The disposition message is "([^"]+)`)
			found = exp.FindStringSubmatch(bodyString)
			if len(found) > 1 {
				errorString = found[1]
			} else {
				errorString = "Unknown error occured"
				klog.Errorf(bodyString)
			}
			klog.Errorf("Couldn't obtain new certificate ID")
			return certStatus, "", "", fmt.Errorf(errorString)
		}
	}

	return s.GetExistingCertificate(certId)
}

func (s *NtlmCertsrv) obtainCaCertificate(certPage string, expectedContentType string) (string, error) {

	// Check for newest renewal number
	url := fmt.Sprintf("%s/%s", s.url, certcarc)
	// klog.V(4).Infof("inside obtainCaCertificate: going to url: %v ", url)
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(s.username, s.password)
	req.Header.Set("User-agent", "Mozilla")
	res1, err := s.httpClient.Do(req)
	// klog.V(4).Infof("Response when obtainingCaCertificate: %v ", res1)

	if err != nil {
		klog.Errorf("ADCS Certserv error: %s", err.Error())
		return "", err
	}
	defer res1.Body.Close()
	body, err := ioutil.ReadAll(res1.Body)
	if err != nil {
		klog.Errorf("Cannot read ADCS Certserv response: %s", err.Error())
		return "", err
	}

	renewal := "0"
	exp := regexp.MustCompile(`var nRenewals=([0-9]+);`)
	found := exp.FindStringSubmatch(string(body))
	if len(found) > 1 {
		renewal = found[1]
	} else {
		klog.Warningf("Renewal not found. Using '0'.")
	}

	// Get CA cert (newest renewal number)
	url = fmt.Sprintf("%s/%s?ReqID=CACert&ENC=b64&Renewal=%s", s.url, certPage, renewal)
	req, _ = http.NewRequest("GET", url, nil)
	req.SetBasicAuth(s.username, s.password)
	req.Header.Set("User-agent", "Mozilla")

	res2, err := s.httpClient.Do(req)

	// klog.V(4).Infof("Response Getting CAcert obtainingCaCertificate: %v ", res2)

	if err != nil {
		klog.Errorf("ADCS Certserv error: %s", err.Error())
		return "", err
	}
	defer res2.Body.Close()

	if res2.StatusCode == http.StatusOK {
		ct := res2.Header.Get(http.CanonicalHeaderKey("content-type"))
		if expectedContentType != ct {
			err = fmt.Errorf("Unexpected content type %s:", ct)
			klog.Errorf(err.Error())
			return "", err
		}
		body, err := ioutil.ReadAll(res2.Body)
		if err != nil {
			klog.Errorf("Cannot read ADCS Certserv response: %s", err.Error())
			return "", err
		}
		// klog.V(4).Infof("return body adcs certserv response: %v ", body)
		return string(body), nil
	}
	return "", fmt.Errorf("ADCS Certsrv response status %s. Error: %s", res2.Status, err.Error())
}
func (s *NtlmCertsrv) GetCaCertificate() (string, error) {
	klog.Infof("Getting CA from ADCS Certsrv %s", s.url)
	return s.obtainCaCertificate(certnew_cer, ct_pkix)
}
func (s *NtlmCertsrv) GetCaCertificateChain() (string, error) {
	klog.Infof("Getting CA Chain from ADCS Certsrv %s", s.url)
	return s.obtainCaCertificate(certnew_p7b, ct_pkcs7)
}
