module Scanny
  module Checks
    class InputFilteringCheck < Check
      def pattern
        [
          pattern_logger_with_params,
          pattern_env_http,
          pattern_params
        ].join("|")
      end

      def check(node)
        issue :low, warning_message, :cwe => 20
      end

      private

      def warning_message
        "Possible injection vulnerabilities"
      end

      # logger(params[:password])
      def pattern_logger_with_params
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

      # params[:input]
      def pattern_params
        <<-EOT
          SendWithArguments<
            name = :[],
            receiver = Send<name = :params>
          >
        EOT
      end

      # env["HTTP_HEADER"]
      # headers["HTTP_HEADER"]
      def pattern_env_http
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                any*,
                StringLiteral<string ^= "HTTP_">,
                any*
              ]
            >,
            name = :[],
            receiver = Send<name = :env | :headers>
          >
        EOT
      end
    end
  end
end