module Scanny
  module Checks
    # Check for logger methods that are called with request params or
    # a dynamic string. This allows us to avoid executing dangerous code.
    class XssLoggerCheck < Check
      def pattern
        [
          pattern_params,
          pattern_dynamic_string,
        ].join("|")
      end

      def check(node)
        issue :low, warning_message, :cwe => 79
      end

      private

      def warning_message
        "Assigning request parameters into logger can lead to XSS issues."
      end

      # logger params[:password]
      def pattern_params
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                SendWithArguments<
                  name = :[],
                  receiver = Send<name = :params>
                >
              ]
            >,
            name = :logger
          >
        EOT
      end

      # logger "#{secure_data}"
      def pattern_dynamic_string
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                DynamicString<
                  array = [
                    any*,
                    ToString,
                    any*
                  ]
                >
              ]
            >,
            name = :logger
          >
        EOT
      end
    end
  end
end