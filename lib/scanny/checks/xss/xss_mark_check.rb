module Scanny
  module Checks
    # Check for methods mark_as_xss_protected and mark_methods_as_xss_safe
    # that are called and can mark dangerous string as safe for html.
    class XssMarkCheck < Check
      def pattern
        pattern_mark_as
      end

      def check(node)
        issue :info, warning_message, :cwe => 0
      end

      private

      def warning_message
        "Marking string as safe can lead to XSS issues."
      end

      # mark_as_xss_protected
      def pattern_mark_as
        <<-EOT
          Send<name = :mark_as_xss_protected | :mark_methods_as_xss_safe>
        EOT
      end
    end
  end
end