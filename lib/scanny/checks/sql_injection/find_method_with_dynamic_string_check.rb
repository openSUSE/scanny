require_relative "sql_check"

module Scanny
  module Checks
    module Sql
      # Check for methods executing external params on
      # database engine with dynamic string
      class FindMethodWithDynamicStringCheck < SqlCheck
        def pattern
          pattern_find_by_with_conditions_dynamic_string
        end

        def check(node)
          issue :medium, warning_message, :cwe => 89
        end

        private

        # find(:first, :conditions => "#{string}")
        def pattern_find_by_with_conditions_dynamic_string
          <<-EOT
            SendWithArguments<
              arguments = ActualArguments<
                array = [
                  any+,
                  HashLiteral<
                    array = [
                      any{even},
                      SymbolLiteral<value = :conditions>,
                      DynamicString,
                      any{even}
                    ]
                  >
                ]
              >,
              name = :find
            >
          EOT
        end
      end
    end
  end
end