module Scanny
  module Checks
    class InputFilteringCheck < Check
      def pattern
        pattern_params
      end

      def check(node)
        issue :low, warning_message, :cwe => 20
      end

      private

      def warning_message
        "Possible injection vulnerabilities"
      end

      # params[:input]
      def pattern_params
        <<-EOT
          SendWithArguments<
            name = :[],
            receiver = Send<name = :params>
          >
        EOT
      end
    end
  end
end