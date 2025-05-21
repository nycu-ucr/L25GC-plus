# Guide to Upgrading L25GC+ Based on free5GC

## Control Plane Module Replacements
- Replace the following modules in the control plane with NYCU-UCR's customized submodules:
    - `gonet`, `net`, `oauth2`, `gock`, `openapi`, `sse`, `gin`, `util`, `ngap`, `nas`

### Go Networking Modules

| Original Import Path              | Replacement                          |
|----------------------------------|--------------------------------------|
| `net/http`                       | `github.com/nycu-ucr/gonet/http`     |
| `golang.org/x/net`              | `github.com/nycu-ucr/net`            |
| `golang.org/x/oauth2/internal`  | `github.com/nycu-ucr/oauth2/internal`|
| `github.com/h2non/gock`         | `github.com/nycu-ucr/gock`           |


### Gin Framework

| Original Import Path             | Replacement                |
|----------------------------------|----------------------------|
| `github.com/gin-gonic/gin`      | `github.com/nycu-ucr/gin`  |
| `github.com/gin-contrib/sse`    | `github.com/nycu-ucr/sse`  |


### Other Module Replacements
- nas
    - `github.com/free5gc/nas` -> `github.com/nycu-ucr/nas`
    - Also replace related OpenAPI dependencies.

- ngap
    - `github.com/free5gc/ngap` -> `github.com/nycu-ucr/ngap`
    - Also replace related OpenAPI dependencies.

- openapi
    - `github.com/free5gc/openapi` → `github.com/nycu-ucr/openapi`  
    -  Also replace the following internal modules: `gonet`, `oauth2`, `net`
    - modify `client.go` to support ONVM-based transport:
        ```diff
        --- a/client.go
        +++ b/client.go

        + const (
        + 	USE_ONVM_CONN      = false
        + 	USE_ONVM_CONN_XIO  = true
        + 	USE_ONVM_TRANSPORT = true
        + )

        @@ -68,6 +75,21 @@  var
        + 	innerHTTP2OnvmClient = &http.Client{
        + 		Transport: &http2.Transport{
        + 			AllowHTTP: true,
        + 			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
        + 				return onvmpoller.DialONVM("onvm", addr)
        + 			},
        + 		},
        + 	}
        + 	innerHTTP2OnvmTransportClient = &http.Client{
        + 		Transport: &http2.OnvmTransport{
        + 			UseONVM: USE_ONVM_CONN,
        + 			UseXIO:  USE_ONVM_CONN_XIO,
        + 		},
        + 	}

        @@ -175,10 +175,21 @@ func CallAPI(cfg Configuration, request *http.Request) (*http.Response, error) {
        -	if request.URL.Scheme == "https" {
        - 		return innerHTTP2Client.Do(request)
        - 	} else if request.URL.Scheme == "http" {
        - 		return innerHTTP2CleartextClient.Do(request)
        + 	if USE_ONVM_CONN || USE_ONVM_CONN_XIO {
        + 		if USE_ONVM_TRANSPORT {
        + 			// ONVM transport with onvm connection
        + 			return innerHTTP2OnvmTransportClient.Do(request)
        + 		} else {
        + 			// HTTP2 transport with onvm connection
        + 			return innerHTTP2OnvmClient.Do(request)
        + 		}
        + 	} else {
        + 		// HTTP2 transport with tcp connection
        + 		if request.URL.Scheme == "https" {
        + 			return innerHTTP2Client.Do(request)
        + 		} else if request.URL.Scheme == "http" {
        + 			return innerHTTP2CleartextClient.Do(request)
        + 		}

        ```

### Network Functions

- Replace each NF module with its NYCU-UCR equivalent:
    - `github.com/free5gc/amf` -> `github.com/nycu-ucr/amf`
    - `github.com/free5gc/nrf` -> `github.com/nycu-ucr/nrf`
    - `github.com/free5gc/ausf` -> `github.com/nycu-ucr/ausf`
    - `github.com/free5gc/udm` -> `github.com/nycu-ucr/udm`
    - `github.com/free5gc/udr` -> `github.com/nycu-ucr/udr`
    - `github.com/free5gc/pcf` -> `github.com/nycu-ucr/pcf`
    - `github.com/free5gc/nssf` -> `github.com/nycu-ucr/nssf`
    - `github.com/free5gc/smf` -> `github.com/nycu-ucr/smf`
    - `github.com/free5gc/chf` -> `github.com/nycu-ucr/chf`
    - Make sure all previously mentioned modules (openapi, nas, ngap, etc.) are also replaced within each NF.


#### Additional Note
- Make sure to also update each NF's configuration file.
