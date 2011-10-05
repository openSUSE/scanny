module Scanny
  module Checks
    # Checks for places where :secret hash key is set.
    class SetSecretCheck < Check
      def pattern
        <<-EOT
          HashLiteral<
            array = [any{even}, SymbolLiteral<value = :secret>, any{odd}]
          >
        EOT
      end

      def check(node)
        issue :info,
          "Setting :secret can indicate using hard-coded cryptographic key.",
          :cwe => 321
      end
    end
  end
end
