module Scanny
  module Checks
    module InsecureMethod
      class SystemMethodCheck < Check
        def pattern
          [
            pattern_system_calls,
            pattern_file_utils_methods,
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

        # FileUtils.mv("one_file", "sec_file")
        def pattern_file_utils_methods
          <<-EOT
            SendWithArguments<
              receiver = ConstantAccess<name = :FileUtils>,
              name = :mv | :cp
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