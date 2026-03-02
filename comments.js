const https = require('https');
const fs = require('fs');
const path = require('path');

// Load SSL/TLS certificates from secure location
const options = {
    key: fs.readFileSync(path.join(__dirname, 'certs', 'private-key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'certs', 'certificate.pem')),
    // Enforce strong TLS version
    minVersion: 'TLSv1.2',
    // Disable older, vulnerable cipher suites
    ciphers: 'HIGH:!aNULL:!MD5:!eNULL',
    // Prevent clickjacking attacks
    headers: {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    }
};

// Create HTTPS server with security options
const server = https.createServer(options, (req, res) => {
    // Sanitize incoming requests
    if (req.url.includes('..')) {
        res.writeHead(400);
        res.end('Bad Request');
        return;
    }
    
    // Set security headers on response
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    
    res.writeHead(200);
    res.end('Secure Server Running');
});

// Listen on restricted port with rate limiting consideration
server.listen(3000, 'localhost');
