module Scanny
  module Checks
    # Check for methods mark_as_xss_protected and mark_methods_as_xss_safe
    # that are called and can mark dangerous string as safe for html.
    class XssMarkCheck < Check
      def pattern
        pattern_mark_as
      end

      def check(node)
        issue :info, "XSS issue", :cwe => 0
      end

      private

        #info           CWE-000                 (mark_as_xss_protected|mark_methods_as_xss_safe)
        def pattern_mark_as
          <<-EOT
            Send<
              name = :mark_as_xss_protected | :mark_methods_as_xss_safe
            >
          EOT
        end
    end
  end
end