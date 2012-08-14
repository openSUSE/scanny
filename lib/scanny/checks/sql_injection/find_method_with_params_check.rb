require_relative "sql_check"

module Scanny
  module Checks
    module Sql
      # Check for methods executing external parameters on
      # database engine with params attribute
      class FindMethodWithParamsCheck < SqlCheck
        def pattern
          [
            pattern_find_by_sql_and_execute_on_models_with_params,
            pattern_find_with_conditions_and_params_or_limit
          ].join("|")
        end

        def check(node)
          issue :high, warning_message, :cwe => 89
        end

        private

        # User.execute(params[:input])
        def pattern_find_by_sql_and_execute_on_models_with_params
          <<-EOT
            SendWithArguments<
              arguments = ActualArguments<
                array = [
                  any*,
                  SendWithArguments<
                    name = :[],
                    receiver = Send<name = :params>
                  >
                  |
                  DynamicString<
                    array = [
                      any*,
                      ToString<
                        value = SendWithArguments<
                          name = :[],
                          receiver = Send<name = :params>
                        >
                      >,
                      any*
                  ]
                  >,
                  any*
                ]
              >,
              name = :execute | :find_by_sql | :paginate,
              receiver = ConstantAccess
            >
          EOT
        end

        # find(:first, :conditions => params[:password])
        def pattern_find_with_conditions_and_params_or_limit
          <<-EOT
            SendWithArguments<
              arguments = ActualArguments<
                array = [
                  any{1,},
                  HashLiteral<
                    array = [
                      any{even},
                      SymbolLiteral<value = :limit | :conditions>,
                      SendWithArguments<
                        name = :[],
                        receiver = Send<name = :params | :session>
                      >,
                      any{even}
                    ]
                  >
                ]
              >,
              name = :find>
          EOT
        end
      end
    end
  end
end