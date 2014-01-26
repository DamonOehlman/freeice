var freeice = require('..');
var quickconnect = require('rtc-quickconnect');

// initialise a configuration for one stun server
var qcOpts = {
  room: 'icetest',
  iceServers: freeice()
};

// go ahead and connect
quickconnect('http://rtc.io/switchboard', qcOpts)
  .createDataChannel('chat')
  .once('chat:open', function(dc, peerId) {
    console.log('data channel opened for peer id: ' + peerId);

    dc.onmessage = function(evt) {
      console.log('peer ' + peerId + ' says: ' + evt.data);
    };

    dc.send('hi');
  });
