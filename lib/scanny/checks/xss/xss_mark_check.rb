module Scanny
  module Checks
    # Check for methods mark_as_xss_protected and mark_methods_as_xss_safe
    # that are called and can mark dangerous string as safe for html.
    class XssMarkCheck < Check
      def pattern
        [
          pattern_mark_as_safe,
          pattern_xss_safe,
          pattern_mark_methods_as_xss_safe
        ].join("|")
      end

      def check(node)
        issue :info, warning_message
      end

      private

      def warning_message
        "Marking string as safe can lead to XSS issues."
      end

      # xss_safe()
      def pattern_xss_safe
        "Send<name = :xss_safe>"
      end

      # mark_as_xss_protected()
      def pattern_mark_as_safe
        <<-EOT
          Send<name =
            :mark_as_xss_protected    |
            :to_s_xss_protected
          >
        EOT
      end

      def pattern_mark_methods_as_xss_safe
        <<-EOT
          SendWithArguments<name = :mark_methods_as_xss_safe>
          |
          Send<name = :mark_methods_as_xss_safe>
        EOT
      end
    end
  end
end