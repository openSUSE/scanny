module Scanny
  module Checks
    # Check for flash method that are called with params or
    # dynamic string. This allows us to avoid showing the user
    # dangerous HTML code.
    class XssFlashCheck < Check
      def pattern
        [
          pattern_params,
          pattern_dynamic_string
        ].join("|")
      end

      def check(node)
        if include_node?(node, Rubinius::AST::SendWithArguments)
          issue :high, "XSS issue", :cwe => 79
        elsif include_node?(node, Rubinius::AST::DynamicString)
          issue :medium, "XSS issue", :cwe => 79
        end
      end

      private

        def include_node?(node, klass)
          node.arguments.array.any? { |node| node.class == klass }
        end

        #high            CWE-79                  flash\[\:warning\]\s*=\s*.*params\s*\[
        def pattern_params
          <<-EOT
            ElementAssignment<
              arguments = ActualArguments<
                array = [
                  SymbolLiteral<value = :warning>,
                  SendWithArguments<
                    name = :[],
                    receiver = Send<
                      name = :params>
                  >
                ]
              >,
              name = :[]=,
              receiver = Send<
                name = :flash
              >
            >
          EOT
        end

        #medium          CWE-79                  flash\[\:warning\]\s*=\s*.*#\{
        def pattern_dynamic_string
          <<-EOT
            ElementAssignment<
              arguments = ActualArguments<
              array = [
                SymbolLiteral<
                  value = :warning
                >,
                DynamicString<
                  array = [
                    ToString<
                      value = Send<name = any>
                    >
                  ]
                >
              ]
              >,
              name = :[]=,
              receiver = Send<
                name = :flash
              >
            >
          EOT
        end
    end
  end
end