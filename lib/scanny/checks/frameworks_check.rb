module Scanny
  module Checks
    class FrameworksCheck < Check
      def pattern
        [
          pattern_xss_safe,
          pattern_mark_as_safe,
          pattern_http_username
        ].join("|")
      end

      def check(node)
        issue :info, warning_message, :cwe => 0
      end

      private

      def warning_message
        "Using the methods from frameworks can lead to security problems"
      end

      def pattern_xss_safe
        "Send<name = :xss_safe>"
      end

      def pattern_mark_as_safe
        <<-EOT
          Send<name =
            :mark_as_xss_protected |
            :mark_methods_as_xss_safe |
            :to_s_xss_protected
          >
        EOT
      end

      def pattern_http_username
        "StringLiteral<string *= /HTTP_X_USERNAME/>"
      end
    end
  end
end