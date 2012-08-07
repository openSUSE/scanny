module Scanny
  module Checks
    # Check for flash methods that are called with request params or
    # dynamic a string. This allows us to avoid showing dangerous
    # HTML code to users
    class XssFlashCheck < Check
      def pattern
        [
          pattern_params,
          pattern_dynamic_string
        ].join("|")
      end

      def check(node)
        if Machete.matches?(node, pattern_params)
          issue :high, warning_message, :cwe => 79
        elsif Machete.matches?(node, pattern_dynamic_string)
          issue :medium, warning_message, :cwe => 79
        end
      end

      private

      def warning_message
        "Assigning request parameters into flash can lead to XSS issues."
      end

      # flash[:warning] = params[:password]
      def pattern_params
        <<-EOT
          ElementAssignment<
            arguments = ActualArguments<
              array = [
                SymbolLiteral<value = :warning>,
                SendWithArguments<
                  name = :[],
                  receiver = Send<name = :params>
                >
              ]
            >,
            name = :[]=,
            receiver = Send<name = :flash>
          >
        EOT
      end

      # flash[:warning] = "#{secure_data}"
      def pattern_dynamic_string
        <<-EOT
          ElementAssignment<
            arguments = ActualArguments<
              array = [
                SymbolLiteral<value = :warning>,
                DynamicString<
                  array = [
                    any*,
                    ToString,
                    any*
                  ]
                >
              ]
            >,
            name = :[]=,
            receiver = Send<name = :flash>
          >
        EOT
      end
    end
  end
end