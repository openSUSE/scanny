require_relative "sql_check"

module Scanny
  module Checks
    module Sql
      # Checks for use of dynamic strings in when creating an SQL query
      class StringInterpolationWithParamsCheck < SqlCheck
        def pattern
          pattern_params_in_select
        end

        def check(node)
          issue :high, warning_message, :cwe => 89
        end

        private

        # "SELECT params[:input] FROM users"
        def pattern_params_in_select
          <<-EOT
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
              ],
              string ^= "SELECT"
            >
          EOT
        end
      end
    end
  end
end