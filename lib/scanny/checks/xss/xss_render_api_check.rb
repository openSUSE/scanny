module Scanny
  module Checks
    # Check for render_api_error method that are called with params or
    # dynamic string. This allows us to avoid executing dangerous
    # code on exception handler UI.
    class XssRenderApiCheck < Check
      def pattern
        [
          render_api_error_with_params,
          render_api_error_with_dynamic_string
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

        #high            CWE-79                  render_api_error.*params\s*\[
        def render_api_error_with_params
          <<-EOT
            SendWithArguments<
              name = :render_api_error,
              arguments = ActualArguments<
                array = [
                  any*,
                  SendWithArguments<
                    receiver = Send<name = :params>
                  >,
                  any*
                ]
              >
            >
          EOT
        end

        #medium          CWE-79                  render_api_error.*#\{
        def render_api_error_with_dynamic_string
          <<-EOT
            SendWithArguments<
              arguments = ActualArguments<
                array = [
                  DynamicString<
                    array = [
                      ToString<
                        value = Send<name = any>
                      >
                    ]
                  >
                ]
              >,
              name = :render_api_error
            >
          EOT
        end
    end
  end
end