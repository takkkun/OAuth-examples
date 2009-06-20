require 'base64'
require 'cgi'
require 'md5'
require 'net/http'
require 'openssl'
require 'uri'

module OAuth
  class Consumer
    attr_accessor :key, :secret, :signature_method, :token

    def initialize(key, secret, options = {})
      @key, @secret = key, secret
      @signature_method = options.delete :signature_method
      @token = options.delete :token
    end

    def get_token(url, parameters = {})
      Token.from_response post(url, parameters)
    end

    def request(method, url, parameters = {})
      uri = URI.parse url
      Net::HTTP.version_1_2
      Net::HTTP.start uri.host, uri.port do |http|
        oauth_parameters = create_oauth_parameters method, url, parameters
        data = OAuth.escape_and_join oauth_parameters.update parameters
        request_class = get_request_class method
        args = request_class.new('/').request_body_permitted? ?
               [request_class.new(uri.path), data] :
               [request_class.new("#{uri.path}?#{data}")]
        http.request *args
      end
    end

    Net::HTTP.constants.each do |method|
      next unless Class === Net::HTTP.const_get(method)
      method.downcase!
      define_method method do |*args|
        request *args.unshift(method)
      end
    end

    private

    def create_oauth_parameters(method, url, parameters)
      oauth_parameters = {
        :oauth_version          => '1.0',
        :oauth_nonce            => MD5.new("#{Time.now.to_f}#{rand}").hexdigest,
        :oauth_timestamp        => Time.now.to_i,
        :oauth_consumer_key     => @key,
        :oauth_signature_method => @signature_method.name
      }
      oauth_parameters[:oauth_token] = @token.token if @token
      sign oauth_parameters, method, url, parameters
    end

    def sign(oauth_parameters, method, url, parameters)
      method = method.to_s.upcase.gsub '_', '-'
      parameters = oauth_parameters.update(parameters).sort_by {|k, v| k.to_s}
      data = OAuth.escape_and_join parameters
      key = OAuth.escape_and_join [@secret, @token && @token.secret]
      message = OAuth.escape_and_join [method, url, data]
      signature = @signature_method.digest key, message
      oauth_parameters.merge :oauth_signature => signature
    end

    def get_request_class(method)
      request_class_name = method.to_s.split('_').map(&:capitalize).join
      unless Net::HTTP.const_defined? request_class_name
        raise NameError, "Not supported #{method} HTTP method"
      end
      Net::HTTP.const_get request_class_name
    end
  end

  class InvalidTokenResponse < Exception
  end

  class Token < Hash
    def self.from_response(response)
      raise InvalidTokenResponse unless response.code == '200'
      options = response.body.split('&').inject({}) do |h, p|
        k, v = p.split '='
        h.merge k.to_sym => v
      end
      token = options.delete :oauth_token
      secret = options.delete :oauth_token_secret
      new(token, secret).merge options
    end

    attr_accessor :token, :secret

    def initialize(token, secret)
      super()
      @token, @secret = token, secret
    end
  end

  module SignatureMethod
    class Base
      class << self
        def name
          super.sub(/^OAuth::SignatureMethod::/, '').gsub('::', '-').upcase
        end

        def digest(key, message)
          raise
        end
      end
    end

    class PlainText < Base
      def self.digest(key, message)
        OAuth.escape key
      end
    end

    module HMAC
      class SHA1 < Base
        def self.digest(key, message)
          digest = OpenSSL::HMAC.digest OpenSSL::Digest::SHA1.new, key, message
          Base64.encode64 digest
        end
      end
    end
  end

  class << self
    def escape(input)
      replacements = {'%7E' => '~', '+' => ' '}
      CGI.escape(input.to_s).gsub(/%7E|\+/) {|m| replacements[m]}
    end

    def escape_and_join(inputs)
      inputs.map do |i|
        Array === i ? "#{escape i[0]}=#{escape i[1]}" : escape(i)
      end.join '&'
    end
  end
end
