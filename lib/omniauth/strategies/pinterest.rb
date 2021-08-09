require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Pinterest < OmniAuth::Strategies::OAuth2
      option :client_options, {
        site: 'https://api.pinterest.com/',
        authorize_url: 'https://pinterest.com/oauth/',
        token_url: 'https://api.pinterest.com/v5/oauth/token'
      }

      def request_phase
        options[:scope] ||= 'read_public'
        options[:response_type] ||= 'code'
        super
      end

      uid { raw_info['id'] }

      info { raw_info }

      def authorize_params
        super.tap do |params|
          %w[redirect_uri].each do |v|
            params[:redirect_uri] = request.params[v] if request.params[v]
          end
        end
      end

      def token_params
        super.tap do |params|
          params[:headers] = { Authorization: "Basic #{Base64.strict_encode64(options[:client_id].to_s + ':' + options[:client_secret].to_s)}" }
        end
      end

      def build_access_token
        verifier = request.params["code"]
        client.auth_code.get_token(verifier, {:redirect_uri => callback_url.split('?')[0]}.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
      end

      def raw_info
        @raw_info ||= {} # There is no endpoint to get user information
      end

      def ssl?
        true
      end
    end
  end
end
