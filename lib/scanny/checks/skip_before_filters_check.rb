module Scanny
  module Checks
    # Checks for use of the "before_filter" method with :login_required,
    # :admin_required, :verify_authenticity_token or :authenticate filters.
    class SkipBeforeFiltersCheck < Check
      def pattern
        <<-EOT
          SendWithArguments<
            receiver  = Self,
            name      = :skip_before_filter,
            arguments = ActualArguments<
              array = [
                any*,
                SymbolLiteral<
                  value = :login_required
                        | :admin_required
                        | :verify_authenticity_token
                        | :authenticate
                >,
                any*
              ]
            >
          >
        EOT
      end

      def check(node)
        filter_node = node.arguments.array.find do |argument|
          argument.is_a?(Rubinius::AST::SymbolLiteral) &&
            [
              :login_required,
              :admin_required,
              :verify_authenticity_token,
              :authenticate
            ].include?(argument.value)
        end

        issue :info,
          "The \"skip_before_filter\" method with :#{filter_node.value} filter is used.",
          :cwe => [285, 288, 425]
      end
    end
  end
end
