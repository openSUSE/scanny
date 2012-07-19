module Scanny
  module Checks
    class FrameworksCheck < Check
      def pattern
        pattern_http_username
      end

      def check(node)
        issue :info, warning_message, :cwe => 0
      end

      private

      def warning_message
        "Using the methods from frameworks can lead to security problems"
      end

      # env["HTTP_X_USERNAME"]
      def pattern_http_username
        "StringLiteral<string *= /HTTP_X_USERNAME/>"
      end
    end
  end
end