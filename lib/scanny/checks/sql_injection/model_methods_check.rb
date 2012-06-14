module Scanny
  module Checks
    module Sql
      class ModelMethodsCheck < Check
        def pattern
          [
          ].join("|")
        end

        def check(node)
          if Machete.matches?(node, pattern_find_by_with_params)
            issue :low, warning_message, :cwe => 89
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
      end
    end
  end
end