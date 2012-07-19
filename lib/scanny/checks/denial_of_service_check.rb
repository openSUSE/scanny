module Scanny
  module Checks
    class DenialOfServiceCheck < Check
      def pattern
        pattern_find_with_like
      end

      def check(node)
        issue :medium, warning_message, :cwe => 400
      end

      private

      def warning_message
        "Using \"LIKE\" in queries may lead to " +
        "the unavailability of the application"
      end

      # User.find(:first, :conditions => "user LIKE %pattern%")
      def pattern_find_with_like
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                any*,
                HashLiteral<
                  array = [
                    any*,
                    SymbolLiteral<value = :limit | :conditions>,
                    StringLiteral<string *= 'LIKE'>,
                    any*
                  ]
                >,
                any*
              ]
            >,
            name *= /^find/
          >
        EOT
      end
    end
  end
end