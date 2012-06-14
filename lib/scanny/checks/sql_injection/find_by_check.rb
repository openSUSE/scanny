module Scanny
  module Checks
    class FindByCheck < Check
      def pattern
        [
          pattern_find_by_with_params,
          pattern_find_by_with_conditions,
          pattern_find_by_with_conditions_dynamic_string,
          pattern_find_with_conditions_and_params_or_limit
        ].join("|")
      end

      def check(node)
        if Machete.matches?(node, pattern_find_by_with_params)
          issue :low, warning_message, :cwe => 89
        elsif Machete.matches?(node, pattern_find_by_with_conditions_dynamic_string)
          issue :medium, warning_message, :cwe => 89
        elsif Machete.matches?(node, pattern_find_with_conditions_and_params_or_limit)
          issue :high, warning_message, :cwe => 89
        elsif Machete.matches?(node, pattern_find_by_with_conditions)
          issue :low, warning_message, :cwe => 89
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
    end
  end
end