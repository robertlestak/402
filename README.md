# 402

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
                "address": "",
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

## Address Management

If the upstream provides a `payment.requests[*].address`, 402 will assume the upstream desires a static address and will use this address. If the upstream leaves the address field empty, 402 will create a new one-time-use address and store the public and private key in Vault. On each reload, a new dedicated address will be created.

## Methods

### Header

Server can enable hpay on an endpoint by sending the following headers. hpay will make a `HEAD` request to a resource to determine if payment is required. `402` will cache the `HEAD` response for `60 minutes`. The header cache can be purged by an administrator by issuing a `PURGE` request to the endpoint with a valid admin JWT.

#### Headers

`x-402-required: [Boolean]`
`x-402-request: [String Base64 JSON]`

### HTML

Serverless / static sites can enable hpay on a resource by setting `<meta>` tags in the `HTML` content (preferrably in the `<head>`).

#### Meta Tags

```html
<meta name="x-402-required" content="[Boolean]">
<meta name="x-402-request" content="[String Base64 JSON]">
```

## Encrypted Checksum

client/server communication with 402 is completely stateless and claims-based. When a client requests access to a resource, 402 will send the client an encrypted payload representing the 402 claims config from the upstream, along with a hashed checksum of the encrypted data. 

When a client sends a transaction to 402, they must include the full encrypted data and meta hash along with the transaction data. 402 will validate the checksum matches the encrypted request before decrypting the request and processing for the user.

## Address Management

402 will create a new address in Vault for each transaction request.

on payment complete, update vault to add txid to the wallet in question.

TODO: unused address clean-up / re-use? pre-generating addresses for faster loading?