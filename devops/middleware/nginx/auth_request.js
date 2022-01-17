function fetch(r) {
    return ngx.fetch('http://402-endpoint/',
        {
            body: null, 
                headers: {
                    'x-402-token': r.headersIn['X-402-Token'],
                    'Cookie': r.headersIn['Cookie']
                }
        })
}

function authorize(r) {
        fetch(r)
            .then((reply) => {
                r.error(reply.status);
                if (reply.status == 200) {
                    r.return(200)
                } else {
                    r.status = 401;
                    r.sendHeader();
                    r.finish()
                    
                }
            })
}


function display402(r) {
    fetch(r)
            .then(reply => reply.text())
            .then(body => r.return(402, body))
            .catch(e => r.return(501, e.message));
}


export default {authorize, display402}
