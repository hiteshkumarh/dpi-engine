const http = require('http');
const fs = require('fs');

const boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW';
let data = '';
const req = http.request({
    hostname: 'localhost',
    port: 5000,
    path: '/api/analyze',
    method: 'POST',
    headers: {
        'Content-Type': 'multipart/form-data; boundary=' + boundary
    }
}, res => {
    res.on('data', c => data += c);
    res.on('end', () => console.log('Response:', data));
});
req.write('--' + boundary + '\r\nContent-Disposition: form-data; name="rules"\r\n\r\nyoutube\r\n');
req.write('--' + boundary + '\r\nContent-Disposition: form-data; name="pcap"; filename="test_dpi.pcap"\r\nContent-Type: application/vnd.tcpdump.pcap\r\n\r\n');
req.write(fs.readFileSync('../test_dpi.pcap'));
req.write('\r\n--' + boundary + '--\r\n');
req.end();
