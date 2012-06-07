module Scanny
  module Checks
    class XssLoggerCheck < Check
      def pattern
        [
          send_params_to_logger,
          send_dynamic_string_to_logger,
        ].join("|")
      end

      def check(node)
        issue :low, "XSS issue", :cwe => 79
      end

      private

        #low             CWE-79                  logger.*params\s*\[
        def send_params_to_logger
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
        def send_dynamic_string_to_logger
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