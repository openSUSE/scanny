module Scanny
  module Checks
    class HTTPRedirectCheck < Check
      def pattern
        [
          pattern_open_struct,
          pattern_open_uri
        ].join("|")
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
        "StringLiteral<string = 'open-uri'>"
      end

      # OpenStruct.new(key: value)
      def pattern_open_struct
        <<-EOT
          Send<
            receiver = ConstantAccess<name = :OpenStruct>
          >
          |
          SendWithArguments<
            receiver = ConstantAccess<name = :OpenStruct>
          >
        EOT
      end
    end
  end
end