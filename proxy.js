#!/usr/bin/env node

// Proxy keyserver to work around the lack of CORS support in existing hkp servers.
// Slightly modified from code by Ryan Alexander:
//   https://github.com/notlion/flickr-pano/blob/master/proxy.js

'use strict'
var http = require('http')
var url = require('url')
var dns = require('dns')

// For now, the key server is hard coded
var keyserver = 'subkeys.pgp.net'

// Unfortunately, the above keyserver doesn't work, since a DNS lookup gives multiple
// addresses only some of which work.  Therefore, we pick one functional IP address.
// For more details, see
//   http://stackoverflow.com/questions/15227154/inexplicable-node-js-http-throwing-connect-econnrefused-ipv6
// TODO: The correct behavior is to try the multiple address one at a time to see which one actually works.
keyserver = '195.113.19.83'

// Use standard keyserver ports
var proxy_port = 11371
var server_port = 11371

// Whether or not to spew debug information
var debug = false

var server = http.createServer(function (req, res) {
  console.log('request',req.url)
  if (debug)
    console.log('request headers',req.headers)

  var ks_req = {
    host: keyserver,
    port: server_port,
    path: req.url
  }
  if (debug)
    console.log('server request headers',ks_req)

  http.get(ks_req,
    function (ks_res) {
      if (debug) {
        console.log('response status',ks_res.statusCode)
        console.log('response headers',ks_res.headers)
      }
      ks_res.headers['access-control-allow-origin'] = '*'
      res.writeHead(ks_res.statusCode,ks_res.headers)
      ks_res.on('data', function (chunk) {
        res.write(chunk, 'binary'); // Forward data to client
      })
      ks_res.on('end', function () {
        res.end()
      })
    }).on('error', function (error) {
      console.error('forwarded request failed',error)
      res.writeHead(404)
      res.end()
    })
})
  
server.listen(proxy_port, function () {
  console.log('server = '+keyserver+':'+server_port)
  console.log('proxy port = '+proxy_port)
})
