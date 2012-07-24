module Scanny
  module Checks
    class HTTPUsageCheck < Check
      def pattern
        pattern_http_url
      end

      def check(node)
        issue :low, warning_message, :cwe => 319
      end

      private

      def warning_message
        "Connecting to the server without encryption " +
        "can facilitate sniffing traffic"
      end

      # "http://example.com"
      def pattern_http_url
        <<-EOT
          StringLiteral<string *= "http://">
        EOT
      end
    end
  end
end