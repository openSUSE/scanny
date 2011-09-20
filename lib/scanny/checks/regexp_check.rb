module Scanny
  module Checks
    # Checks for possible improper regular expression usage.
    class RegexpCheck < Check
      def pattern
        "RegexLiteral | DynamicRegex"
      end

      def check(node)
        if node.is_a?(Rubinius::AST::RegexLiteral)
          improper_start = node.source =~ /^\^/
          improper_end   = node.source =~ /\$$/
        elsif node.is_a?(Rubinius::AST::DynamicRegex)
          improper_start = node.string =~ /^\^/
          improper_end   = node.array.last.is_a?(Rubinius::AST::StringLiteral) &&
                           node.array.last.string =~ /\$$/
        else
          raise "Unexpected node class: #{node.class}."
        end

        return unless improper_start || improper_end

        issue :low, "Possible improper regular expression usage.",
          :cwe => [185, 625, 791]
      end
    end
  end
end
