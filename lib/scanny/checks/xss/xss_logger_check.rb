module Scanny
  module Checks
    # Check for logger methods that are called with request params or
    # a dynamic string. This allows us to avoid executing dangerous code.
    class XssLoggerCheck < Check
      def pattern
        [
          pattern_logger_with_params,
          pattern_dynamic_string,
        ].join("|")
      end

      def check(node)
        issue :low, warning_message, :cwe => [20, 79]
      end

      private

      def warning_message
        "Assigning request parameters into logger can lead to XSS issues."
      end

      # logger(params[:password])
      # logger("User password: #{params[:password]} is...")
      def pattern_logger_with_params
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                any*,
                SendWithArguments<
                  name = :[],
                  receiver = Send<name = :params>
                >
                |
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
                  ]
                >,
                any*
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
                    ToString<
                      value = Send<name = any>
                    >
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