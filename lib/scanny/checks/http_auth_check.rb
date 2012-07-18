module Scanny
  module Checks
    class VerifyMethodCheck < Check
      def pattern
        pattern_verify
      end

      def check(node)
        issue :info, warning_message, :cwe => 0
      end

      private

      def warning_message
        "Incorrect to use the verify method can lead to " +
        "accept additional parameters from request"
      end

      # verify :method => :post, :only => [:create]
      def pattern_verify
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                any*,
                HashLiteral<
                  array = [
                    any*,
                    SymbolLiteral<value = :method>,
                    any*
                  ]
                >,
                any*
              ]
            >,
            name = :verify
          >
        EOT
      end
    end
  end
end
