module Scanny
  module Checks
    # Check for logger method that are called with params or
    # dynamic string. This allows us to avoid executing dangerous code.
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

        #low             CWE-79                  logger.*params\s*\[
        def pattern_params
          <<-EOT
            SendWithArguments<
              arguments = ActualArguments<
                array = [
                  SendWithArguments<
                    name = :[],
                    receiver = Send<
                      name = :params
                    >
                  >
                ]
              >,
              name = :logger
            >
          EOT
        end

        #low             CWE-79                  logger.*#\{
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