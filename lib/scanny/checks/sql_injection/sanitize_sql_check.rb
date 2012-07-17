require_relative "sql_check"

module Scanny
  module Checks
    module Sql
      # Check for use of the "sanitize_sql" method
      class SanitizeCheck < SqlCheck
        def pattern
          pattern_sanitize_sql
        end

        def check(node)
          issue :info, warning_message, :cwe => 89
        end

        private

        # sanitize_sql()
        def pattern_sanitize_sql
          "Send<name = :sanitize_sql>"
        end
      end
    end
  end
end