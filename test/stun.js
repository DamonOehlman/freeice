const stun = require('stun');
const {
  STUN_BINDING_REQUEST,
  STUN_ALLOCATE_REQUEST,
  STUN_ATTR_MAPPED_ADDRESS,
  STUN_ATTR_XOR_MAPPED_ADDRESS,
  RESPONSE_S,
  MAPPED_ADDRESS
} = stun.constants;
const servers = require('../stun.json');
const test = require('tape');
const MAX_RESPONSE_TIME = 10000;
const freeice = require('..');

test('by default 2 stun servers are returned', function(t) {
  var iceServers;

  t.plan(2);
  iceServers = freeice();
  t.ok(Array.isArray(iceServers), 'we have a server array');
  t.equal(iceServers.length, 2, 'we have 2 servers');
});

servers.forEach(url => {
  test(`can connect to ${url}`, t => {
    t.plan(3);
    stun.request(url, { timeout: MAX_RESPONSE_TIME }, (err, stunMsg) => {
      if (err) {
        return t.fail(err);
      }

      const mapped = stunMsg.getAttribute(STUN_ATTR_MAPPED_ADDRESS)
        || stunMsg.getAttribute(STUN_ATTR_XOR_MAPPED_ADDRESS);

      if (mapped) {
        t.equal(mapped.value.family, 'IPv4');
        t.notEqual(mapped.value.port, null);
        t.notEqual(mapped.value.address, null);
      } else {
        t.fail('No valid response found');
      }
    });
  });
});
