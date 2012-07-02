module Scanny
  module Checks
    class InformationLeakCheck < Check
      def pattern
        [
          pattern_logger_filter,
          pattern_find
        ].join("|")
      end

      def check(node)
        issue :medium, warning_message, :cwe => 200
      end

      private

      def warning_message
        "There is a possibility of data leakage"
      end

      def pattern_logger_filter
        <<-EOT
          Send<name = :filter_parameter_logging>
          |
          SendWithArguments<name = :filter_parameter_logging>
        EOT
      end

      def pattern_find
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                any*,
                SendWithArguments<
                  name = :[],
                  receiver = Send<name = :params>
                >,
                any*
              ]
            >,
            name *= /^find/
          >
        EOT
      end
    end
  end
end