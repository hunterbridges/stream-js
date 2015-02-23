
var jsSHA = require("jssha");


function makeUrlSafe(s) {
	/*
	 * Makes the given base64 encoded string urlsafe
	 */
	var escaped = s.replace(/\+/g, '-').replace(/\//g, '_');
	return escaped.replace(/^=+/, '').replace(/=+$/, '');
}


exports.sign = function(apiSecret, feedId) {
	/*
	 * Setup sha1 based on the secret
	 * Get the digest of the value
	 * Base64 encode the result
	 *
	 * Also see
	 * https://github.com/tbarbugli/stream-ruby/blob/master/lib/stream/signer.rb
	 * https://github.com/tschellenbach/stream-python/blob/master/stream/signing.py
	 *
	 * Steps
	 * apiSecret: tfq2sdqpj9g446sbv653x3aqmgn33hsn8uzdc9jpskaw8mj6vsnhzswuwptuj9su
	 * feedId: flat1
	 * digest: Q\xb6\xd5+\x82\xd58\xdeu\x80\xc5\xe3\xb8\xa5bL1\xf1\xa3\xdb
	 * token: UbbVK4LVON51gMXjuKViTDHxo9s
	 */

  var secretObj = new jsSHA(apiSecret, "TEXT");
  var hash = secretObj.getHash("SHA-1", "HEX");
  var digestObj = new jsSHA(feedId, "TEXT");
  var hmac = digestObj.getHMAC(hash, "HEX", "SHA-1", "B64");
  var token = makeUrlSafe(hmac);
	return token;
};
