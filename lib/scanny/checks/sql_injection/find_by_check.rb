module Scanny
  module Checks
    module Sql
      class FindByCheck < Check
        def pattern
          [
            pattern_find_by_with_params,
            pattern_find_by_with_conditions,
            pattern_find_by_with_conditions_dynamic_string,
            pattern_find_with_conditions_and_params_or_limit,
            pattern_find_by_sql_and_execute_on_models,
            pattern_find_by_sql_and_execute_on_models_with_params
          ].join("|")
        end

        def check(node)
          impact(:low) do
            report_issue(pattern_find_by_sql_and_execute_on_models, :cwe => 89)
            report_issue(pattern_find_by_with_params, :cwe => 89)
            report_issue(pattern_find_by_with_conditions, :cwe => 89)
          end

          impact(:medium) do
            report_issue(pattern_find_by_with_conditions_dynamic_string, :cwe => 89)
          end

          impact(:high) do
            report_issue(pattern_find_by_sql_and_execute_on_models_with_params, :cwe => 89)
            report_issue(pattern_find_with_conditions_and_params_or_limit, :cwe => 89)
          end
        end

        private

        def warning_message
         "Use of external parameters in queries to the database " +
         "can lead to SQL injection issue"
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
                  any*,
                  HashLiteral<
                    array = [
                      any*,
                      SymbolLiteral<
                        value = :conditions
                      >,
                      any*
                    ]
                  >,
                  any*
                ]
              >,
              name = :find
            >
          EOT
        end

        # find(:first, :conditions => "#{string}")
        def pattern_find_by_with_conditions_dynamic_string
          <<-EOT
            SendWithArguments<
              arguments = ActualArguments<
                array = [
                  any*,
                  HashLiteral<
                    array = [
                      any*,
                      SymbolLiteral<value = :conditions>,
                      DynamicString,
                      any*
                    ]
                  >,
                  any*
                ]
              >,
              name = :find
            >
          EOT
        end

        # find(:first, :conditions => params[:password])
        def pattern_find_with_conditions_and_params_or_limit
          <<-EOT
            SendWithArguments<
              arguments = ActualArguments<
                array = [
                  any*,
                  HashLiteral<
                    array = [
                      any*,
                      SymbolLiteral<value = :limit | :conditions>,
                      any*,
                      SendWithArguments<
                        name = :[],
                        receiver = Send<name = :params | :session>
                      >,
                      any*
                    ]
                  >,
                  any*
                ]
              >,
              name = :find>
          EOT
        end

        # User.find_by_sql
        def pattern_find_by_sql_and_execute_on_models
          <<-EOT
            Send<
              name = :execute | :find_by_sql | :paginate,
              receiver = ConstantAccess
            >
          EOT
        end

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
                  >,
                  any*
                ]
              >,
              name = :execute | :find_by_sql | :paginate,
              receiver = ConstantAccess
            >
          EOT
        end
      end
    end
  end
end