module Scanny
  module Checks
    # Checks for use of the "before_filter" method with certain filters.
    class BeforeFiltersCheck < Check
      FILTERS = [:login_required, :admin_required]

      def pattern
        <<-EOT
          SendWithArguments<
            receiver  = Self,
            name      = :before_filter,
            arguments = ActualArguments<
              array = [
                any*,
                SymbolLiteral<value = #{FILTERS.map(&:inspect).join(' | ')}>,
                any*
              ]
            >
          >
        EOT
      end

      def check(node)
        filter_node = node.arguments.array.find do |argument|
          argument.is_a?(Rubinius::AST::SymbolLiteral) &&
            FILTERS.include?(argument.value)
        end

        issue :info,
          "The \"before_filter\" method with :#{filter_node.value} filter is used."
      end
    end
  end
end
