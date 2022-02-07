# Running a Local Proxy

When doing local app development, and especially when integrating more deeply with 402, you may find it useful to run a local proxy to represent your "live" gateway.

This can be done with a small NGINX container.

## Connection Requirements

As `402` will needd to connect to your origin to retrieve the auth headers, when running your app in local development, you will need to make it available to `402`. This can be done with a local proxy service such as [ngrok](https://ngrok.com/). You will need to configure your `402` origin to point to your proxy endpoint.

## Configuration

Update `nginx/auth_request.js` to add your `x-402-tenant` id:

```js
function fetch(r) {
    return ngx.fetch('https://api.402.sh/v1/_402?resource=' + r.uri, {
            body: null, 
            verify: false,
                headers: {
                    'x-402-token': r.headersIn['X-402-Token'],
                    'x-402-signature': r.headersIn['X-402-Signature'],
                    'x-402-host': r.headersIn['Host'],
                    'x-402-tenant': "PUT_YOUR_TENANT_ID_HERE",
                    'Cookie': r.headersIn['Cookie']
                }
        })
}
```

Update `nginx/nginx.conf` to point to your backend origin:

```
upstream backend {
    server host.docker.internal:3000;
}
```

In the above example, this is connecting to `localhost:3000` on the local workstation. As mentioned in the **Connection Requirements** section, your proxy endpoint needs to be configured as your `402` origin, however your local `NGINX` can continue to point directly to `localhost` if desired.
