module Scanny
  module Checks
    class HTTPRedirectCheck < Check
      def pattern
        pattern_open_uri
      end

      def check(node)
        issue :medium, warning_message, :cwe => 441
      end

      private

      def warning_message
        "HTTP redirects can be emitted by the Application"
      end

      # require 'open-uri'
      def pattern_open_uri
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                StringLiteral<string = 'open-uri'>
              ]
            >,
            name = :require
          >
        EOT
      end
    end
  end
end