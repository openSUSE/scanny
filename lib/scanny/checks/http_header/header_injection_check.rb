module Scanny
  module Checks
    module HttpHeader
      class HeaderInjectionCheck < Check
        def pattern
          pattern_environment_params
        end

        def check(node)
          issue :medium, warning_message, :cwe => [20, 113]
        end

        private

        def warning_message
          "Directly use of the HTTP_* headers in code"
        end

        def pattern_environment_params
          <<-EOT
            SendWithArguments<
              arguments = ActualArguments<
                array = [
                  StringLiteral<string ^= "HTTP_">
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
end