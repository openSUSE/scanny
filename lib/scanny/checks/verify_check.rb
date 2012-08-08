module Scanny
  module Checks
    class VerifyMethodCheck < Check
      def pattern
        pattern_verify
      end

      def check(node)
        issue :info, warning_message
      end

      private

      def warning_message
        "Incorrect to use the verify method can lead to " +
        "accept additional parameters from request"
      end

      # verify :method => :get
      def pattern_verify
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                HashLiteral<
                  array = [
                    any{even},
                    SymbolLiteral<value = :method>,
                    any{odd}
                  ]
                >
              ]
            >,
            name = :verify
          >
        EOT
      end
    end
  end
end
