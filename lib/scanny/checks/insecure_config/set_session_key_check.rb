module Scanny
  module Checks
    # Checks for places where :session_key hash key is set.
    class SetSessionKeyCheck < Check
      # :session_key
      def pattern
        <<-EOT
          HashLiteral<
            array = [any{even}, SymbolLiteral<value = :session_key>, any{odd}]
          >
        EOT
      end

      def check(node)
        issue :info, "Setting :session_key."
      end
    end
  end
end
