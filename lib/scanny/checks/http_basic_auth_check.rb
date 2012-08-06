module Scanny
  module Checks
    class HTTPBasicAuthCheck < Check
      def pattern
        [
          pattern_basic_auth,
          pattern_http_authentication
        ].join("|")
      end

      def check(node)
        issue :info, warning_message, :cwe => [301, 718]
      end

      private

      def warning_message
        "Basic HTTP authentication can lead to security problems"
      end

      # Net::HTTPHeader.basic_auth('user', 'password')
      def pattern_basic_auth
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [any{2}]
            >,
            name = :basic_auth
          >
        EOT
      end

      # HttpAuthentication
      def pattern_http_authentication
        "ConstantAccess<name = :HttpAuthentication>"
      end
    end
  end
end