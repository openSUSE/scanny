module Scanny
  module Checks
    # Checks for possible improper regular expression usage.
    class RegexpCheck < Check
      def pattern
        <<-EOT
          RegexLiteral<source ^= "^">
          |
          RegexLiteral<source $= "$">
          |
          DynamicRegex<string ^= "^">
          |
          DynamicRegex<array = [any*, StringLiteral<string $= "$">]>
        EOT
      end

      def check(node)
        issue :low, "Possible improper regular expression usage.",
          :cwe => [185, 625, 791]
      end
    end
  end
end
