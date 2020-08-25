# ADCS-Issuer setup for developers

## pre-requisite

- make sure the kubernetes current-context is correctly set to the cluster you want to deploy the ADCS-issuer to.

## build and push the adcs-controller

This step is only needed when debugging / changing code.

- #TODO setup skaffold for better workflow

> IMG=pietere/controller:latest make docker-build docker-push

## webhook certificate

Create a certificate using selfsigned issuer from cert-manager in order to get the  the webhook & controller working.

- #TODO this needs to be added to adcs-controller resources
- #TODO the commonName is hard-coded.

cat <<EOF | kubectl -n adcs-issuer-system apply -f -

``` YAML
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: serving-cert
spec:
  commonName: adcs-issuer-webhook-service.adcs-issuer-system.svc
  dnsNames:
  - adcs-issuer-webhook-service.adcs-issuer-system.svc.cluster.local
  issuerRef:
    kind: ClusterIssuer
    name: selfsigned
  secretName: webhook-server-cert
```

## deploy adcs-issuer controller to k8s-cluster

First deploy the crds:
> make install

Replace the image and deploy the adcs-issuer resources:
> IMG=pietere/controller:latest make deploy

## NTLM

#TODO check where to specify the namespace to deploy the credentials/secret to.

cat <<EOF | kubectl -n kube-system apply -f -

``` YAML
apiVersion: v1
kind: Secret
metadata:
  name: test-adcs-issuer-credentials
type: Opaque
data:
  password: cGFzc3dvcmQ=
  username: dXNlcm5hbWU=
```

## start ADCS-simulator

Run the adcs-simulator in another shell:
> make sim

Get the server.pem / root.pem certificate for the adcs-issuer to authenticate against the ADCS-simulator-server.
> openssl s_client -connect localhost:8443 -showcerts

Encode the certificate to base64 and in one line, for caBundle.
> cat <<EOF | base64 -w 0

## (Cluster) ADCS-Issuer

Deploy the AdcsIssuer to the k8s-cluster.
The ClusterAdcsIssuer is deployed the same way.

cat <<EOF | kubectl -n adcs-issuer-system apply -f -

``` YAML
kind: AdcsIssuer
apiVersion: adcs.certmanager.csf.nokia.com/v1
metadata:
  name: test-adcs-issuer
spec:
  caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM5ekNDQWQrZ0F3SUJBZ0lKQU92T05idHY0OU5OTUEwR0NTcUdTSWIzRFFFQkN3VUFNQkl4RURBT0JnTlYKQkFNTUIwRkVRMU5UYVcwd0hoY05NVGt3TnpJd01Ua3lOekV4V2hjTk1qa3dOekUzTVRreU56RXhXakFTTVJBdwpEZ1lEVlFRRERBZEJSRU5UVTJsdE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBCm1TMjMreXZpRnBURU1HTnQzbHYrSmt3cEFLeEt6QlhSU2MvYkpUWWphOGxTbWc4WTZsQWZrYURBYWdjeUltUkYKY2Y1dzBCNVhVT2R4TFpIM0ROR0VZUEp1bEIzZ2ZlMVYvdm90UzFCZzFMSEtHbWVvS1JYQVZLVERUK25kM3d0KwphQ1l2d2tFVjBjSTRyTnNMd1VWVW5qZktjbEVPTGJQMVRGYUJSOG1VWWdkN0ZqUFd1T1hwbk5Hb3RyNWdkbmhNCmJXVjJ4SEFHWVR5Nno3U05EVHJNQjVWWTVYQVA1ZlRvN09pT2UyUHlnMnFiMmdUMnhUWjZ4OUo0aCtrUTMreEUKRWRaTVVHeUF0WWlFTFhZN3dBZGxwS0hjMDJKejUrVGgzWUdUbWgxbk1MbW84eUpyZUJWMytIVlozVU55TGx6NAppUSszUko1Q2tMcTIxQS9yUW5qZlV3SURBUUFCbzFBd1RqQWRCZ05WSFE0RUZnUVVDTUtMM3htVEUzOWwwbXl0CmxtQkZlU3FabUdBd0h3WURWUjBqQkJnd0ZvQVVDTUtMM3htVEUzOWwwbXl0bG1CRmVTcVptR0F3REFZRFZSMFQKQkFVd0F3RUIvekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBZXdjM2JtZlFDaDNKanJkc2tsMnliWXE3ZTlKRgpFME9JNjgyWEllWWhVUHdUU1pHMy9Od01BbmtlK3QrRmR5TU9ENVNvL2NxQ2VtTGlCVWJGUnR6QmpyTlBJRUplCnUyNTZYekVxbXBDNmw5K0tGQzVqMzZKQ01leFZ6L2hxUnU4SlFJaitOenJBb0prTCtTNzBMdk1QUk90ZDVOS2UKNnQ3d3VmTE9RRkxHanBuU3lyWHEzbGRHZ0JRWGw3bG5JdVVMd0lJak9YcWR6OTFMa2VQbGVCRVV6QUdmZERmTwpJSU9GWWNwMDVoa2lmbm1SSzA1VTJucDAwWGZMakhRZEVRNDdVZ3NPZW9ncXl3UEg4WWRGaUQvRy9WWnVZMmZKCnVWRFNXQVljRHpwTmIzVWUvam5qQlBjTTlqZTB2YVdhZUE4UG10Y3dVeTZlOGdsVjdBZlZOWXVvQ3c9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
  credentialsRef:
    name: test-adcs-issuer-credentials
  statusCheckInterval: 6h
  retryInterval: 1h
  url: https://localhost:8443
```

## Example certificate

Apply a certificate resource, that will make a certificaterequest with the issuerRef pointed to AdcsIssuer.

cat <<EOF | kubectl -n adcs-issuer-system apply -f -

``` YAML
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  annotations:
  name: adcs-certificate
spec:
  commonName: localhost
  dnsNames:
  - service1.example.com
  - service2.example.com
  issuerRef:
    group: adcs.certmanager.csf.nokia.com
    kind: AdcsIssuer
    name: test-adcs-issuer
  organization:
  - Your organization
  secretName: adcsIssuer-certificate
```
