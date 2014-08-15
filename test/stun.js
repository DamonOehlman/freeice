var stun = require('stun');
var servers = require('../stun.json');
var test = require('tape');
var MAX_RESPONSE_TIME = 10000;
var freeice = require('..');

test('by default 2 stun servers are returned', function(t) {
  var iceServers;

  t.plan(2);
  iceServers = freeice();
  t.ok(Array.isArray(iceServers), 'we have a server array');
  t.equal(iceServers.length, 2, 'we have 2 servers');
});

servers.forEach(function(url) {
  test('can connect to ' + url, function(t) {
    var parts = url.split(':');
    var host = parts[0];
    var port = parts[1] ? parseInt(parts[1], 10) : 3478;
    var method = stun.method.RESPONSE_S;
    var attr   = stun.attribute.MAPPED_ADDRESS;
    var client;

    function handleResponse(packet) {
      t.equal(packet.class, 1);
      t.equal(packet.method, method);

      // if we have a xor mapped address, then accept it as ok
      if (packet.attrs[stun.attribute.XOR_MAPPED_ADDRESS]) {
        t.pass('got XOR_MAPPED_ADDRESS in response, not attempting to decode');
        t.pass('skipping port test');
        t.pass('skipping address test');
      }
      else {
        t.equal(packet.attrs[attr].family, 4);
        t.notEqual(packet.attrs[attr].port, null);
        t.notEqual(packet.attrs[attr].address, null);
      }


      // close the client
      client.close();

      // reset the response timer
      clearTimeout(responseTimer);
    }

    t.plan(5);
    console.log('attempting to connect to host: ' + host + ', port: ' + port);
    client = stun.connect(port, host);
    client.once('response', handleResponse);

    responseTimer = setTimeout(function() {
      client.removeListener('response', handleResponse);
      client.removeAllListeners('error');
      client.close();

      t.fail('server did not respond within ' + MAX_RESPONSE_TIME + 'ms');
      t.end();
    }, MAX_RESPONSE_TIME);

    client.on('error', t.ifError.bind(t));
    client.request();
  });
});
