import http from 'k6/http';
import {sleep, check} from 'k6';
import privatebin from 'k6/x/privatebin';


export default function () {
    var params = {
        headers: {
            'X-Requested-With': 'JSONHttpRequest',
        },
    };
    var paste = privatebin.encrypt("hello world!");

    var result = http.post('https://privatebin.net', paste.body, params);
    check(result, {
        'post status 200': (r) => r.status === 200,
        'post ok': (r) => r.json().status == 0,
    });

    var url = `${result.url}?${result.json().id}`;
    var result = http.get(url, params);
    check(result, {
        'get status 200': (r) => r.status === 200,
        'get ok': (r) => r.json().status == 0,
        'get data equal': (r) => JSON.stringify(r.json().adata) === JSON.stringify(JSON.parse(paste.body).adata)
    });

    sleep(1);
}
