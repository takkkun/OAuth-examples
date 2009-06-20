require 'oauth'

CONSUMER_KEY      = 'your consumer key'
CONSUMER_SECRET   = 'your consumer secret'
BASE              = 'http://twitter.com/oauth'
REQUEST_TOKEN_URL = "#{BASE}/request_token"
ACCESS_TOKEN_URL  = "#{BASE}/access_token"
AUTHORIZE_URL     = "#{BASE}/authorize?oauth_token=%s"

# 1. Get request token
consumer = OAuth::Consumer.new CONSUMER_KEY, CONSUMER_SECRET, {
  :signature_method => OAuth::SignatureMethod::HMAC::SHA1
}

request_token = consumer.get_token REQUEST_TOKEN_URL

puts "Request token: #{request_token.token}"
puts "Request token secret: #{request_token.secret}"

# 2. Authorize user(Mac OS X only)
%x{open #{AUTHORIZE_URL % request_token.token}}
puts 'Press enter key after allowed.'
gets

# 3. Get access token
consumer.token = request_token
access_token = consumer.get_token ACCESS_TOKEN_URL

puts "Access token: #{access_token.token}"
puts "Access token secret: #{access_token.secret}"

unless access_token.empty?
  puts 'Optional values:'
  access_token.each_pair {|key, value| puts "  #{key} => #{value}"}
end

# 4. Request to resources on the service provider
consumer.token = access_token
response = consumer.get 'http://twitter.com/statuses/user_timeline.json'

puts response.code
puts response.body
