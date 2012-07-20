require_relative "sql_check"

module Scanny
  module Checks
    module Sql
      # Check for methods executing external params on
      # database engine
      class FindMethodCheck < SqlCheck
        def pattern
          [
            pattern_find_by_sql_and_execute_on_models,
            pattern_find_by_with_params,
            pattern_find_by_with_conditions
          ].join("|")
        end

        def check(node)
          issue :low, warning_message, :cwe => 89
        end

        private

        # User.find_by_sql
        def pattern_find_by_sql_and_execute_on_models
          <<-EOT
            Send<
              name = :execute | :find_by_sql | :paginate,
              receiver = ConstantAccess
            >
          EOT
        end

        # find_by_id(params[:search])
        def pattern_find_by_with_params
          <<-EOT
            SendWithArguments<
              arguments = ActualArguments<
                array = [
                  any*,
                  SendWithArguments<
                    name = :[],
                    receiver = Send<
                      name = :params
                    >
                  >,
                  any*
                ]
              >,
              name ^= :find_by
            >
          EOT
        end

        # find(:first, :conditions => "string")
        def pattern_find_by_with_conditions
          <<-EOT
            SendWithArguments<
              arguments = ActualArguments<
                array = [
                  any{1},
                  HashLiteral<
                    array = [
                      any{even},
                      SymbolLiteral<
                        value = :conditions
                      >,
                      any{odd}
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