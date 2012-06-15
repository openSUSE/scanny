module Scanny
  module Checks
    # Check for render_api_error methods that are called with params or
    # a dynamic string. This allows us to avoid executing dangerous
    # code in the exception handler UI.
    class XssRenderApiCheck < Check
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
        "Assigning request parameters into render_api_error can lead to XSS issues."
      end

      # render_api_error params[:password]
      def pattern_params
        <<-EOT
          SendWithArguments<
            name = :render_api_error,
            arguments = ActualArguments<
              array = [
                any*,
                SendWithArguments<
                  receiver = Send<name = :params>
                >,
                any*
              ]
            >
          >
        EOT
      end

      # render_api_error "#{secure_data}"
      def pattern_dynamic_string
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                DynamicString<
                  array = [
                    ToString<
                      value = Send<name = any>
                    >
                  ]
                >
              ]
            >,
            name = :render_api_error
          >
        EOT
      end
    end
  end
end