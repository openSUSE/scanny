module Scanny
  module Checks
    class XssMarkCheck < Check
      def pattern
        mark_as_check
      end

      def check(node)

        issue :info, "XSS issue", :cwe => 0
      end

      private

        #info           CWE-000                 (mark_as_xss_protected|mark_methods_as_xss_safe)
        def mark_as_check
          <<-EOT
            Send<
              name = :mark_as_xss_protected | :mark_methods_as_xss_safe
            >
          EOT
        end
    end
  end
end