# hpay

```json
{
    "claims": {
        "aud": "hello world",
        "hello": "world"
    },
    "exp": 60000000000,
    "payment": {
        "txid": "123",
        "requests": [
            {
                "network": "polygon",
                "address": "0x1058Df18a09eE6f69e7F0999aB772aFED6b3fb72",
                "amount": 0
            }
        ]
    },
    "customization": {
        "css": "http://localhost:3000/payment-style.css",
        "js": "",
        "image": ""
    }
}
```

## Methods

### Header

Server can enable hpay on an endpoint by sending the following headers. hpay will make a `HEAD` request to a resource to determine if payment is required. `hpay` will cache the `HEAD` response for `60 minutes`. The header cache can be purged by an administrator by issuing a `PURGE` request to the endpoint with a valid admin JWT.

#### Headers

`x-402-required: [Boolean]`
`x-402-request: [String Base64 JSON]`

