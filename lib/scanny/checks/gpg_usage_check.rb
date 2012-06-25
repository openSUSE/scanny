module Scanny
  module Checks
    class GpgUsageCheck < Check
      def pattern
        [
          pattern_gpg_class,
          pattern_gpg_method,
          pattern_gpg_string,
          pattern_gpg_execute_string
        ].join("|")
      end

      def check(node)
        issue :info, warning_message, :cwe => 0
      end

      private

      def warning_message
        "Using gpg tool in the wrong way can lead to security problems"
      end

      def pattern_gpg_class
        <<-EOT
          Send | SendWithArguments
          <
            receiver = ConstantAccess<
              name =
                :GPG |
                :Gpg |
                :GpgKey
            >
          >

        EOT
      end

      def pattern_gpg_method
        "Send | SendWithArguments<name = :gpg>"
      end

      def pattern_gpg_string
        'StringLiteral<string *= "gpg">'
      end

      def pattern_gpg_execute_string
        'ExecuteString<string *= "gpg">'
      end
    end
  end
end