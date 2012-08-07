module Scanny
  module Checks
    module InsecureMethod
      class SystemMethodCheck < Check
        def pattern
          [
            pattern_system_calls,
            pattern_execute_string
          ].join("|")
        end

        def check(node)
          issue :high, warning_message, :cwe => [88, 78]
        end

        private

        def warning_message
          "Execute system commands can lead the system to run dangerous code"
        end

        # system("rm -rf /")
        def pattern_system_calls
          <<-EOT
            SendWithArguments
              <name =
                :popen          |
                :system         |
                :spawn          |
                :exec
              >
          EOT
        end

        # `system_command`
        def pattern_execute_string
          "ExecuteString"
        end
      end
    end
  end
end