module Scanny
  module Checks
    module Sql
      class StringCheck < Check
        def pattern
          [
            pattern_sanitize_sql,
            pattern_options_with_select_in_select,
            pattern_params_in_select
          ].join("|")
        end

        def check(node)
          if Machete.matches?(node, pattern_sanitize_sql)
            issue :info, warning_message, :cwe => 89
          else
            issue :high, warning_message, :cwe => 89
          end
        end

        private

        def warning_message
          "Use of external parameters in queries to the database " +
          "can lead to SQL injection issue"
        end

        def pattern_sanitize_sql
          "Send<name = :sanitize_sql>"
        end

        def pattern_options_with_select_in_select
          <<-EOT
            DynamicString<
              array = [
                any*,
                ToString<
                  value = SendWithArguments<
                    arguments = ActualArguments<
                      array = [
                        SymbolLiteral<value = :select>
                      ]
                    >,
                    name = :[],
                    receiver = Send<name = :options>
                  >
                >,
                any*
              ],
              string ^= "SELECT"
            >
          EOT
        end

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