module Scanny
  module Checks
    class FindByCheck < Check
      def pattern
        find_by_with_params
      end

      def check(node)
        issue :low, warning_message, :cwe => 89
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

      # find_by_id(:conditions => "string")
      def pattern_find_by_with_conditions
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                any*,
                HashLiteral<
                  array = [
                    SymbolLiteral<
                      value = :conditions
                    >
                  ]
                >,
                any*
              ]
            >,
            name ^= :find_by
          >"
        EOT
      end

      # find_by_id(:conditions => "#{string}")
      def pattern_find_by_with_conditions_dynamic_string
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                HashLiteral<
                  array = [
                    SymbolLiteral<
                      value = :conditions
                    >,
                    DynamicString<any>
                  ]
                >
              ]
            >,
            name ^= :find_by
          >
        EOT
      end
    end
  end
end