module Scanny
  module Checks
    # Checks for methods executing external commands that pass the command
    # through shell expansion. This can cause unwanted code execution if the
    # command includes unescaped input.
    class ShellExpandingMethodsCheck < Check
      def pattern
        [
          pattern_shell_expanding,
          pattern_popen,
          pattern_execute_string
        ].join("|")
      end

      def check(node)
        # The command goes through shell expansion only if it is passed as one
        # argument.
        issue :high, warning_message(node), :cwe => [88, 78]
      end

      def warning_message(node = nil)
        name = node.respond_to?(:name) ? node.name : "`"
        "The \"#{name}\" method passes the executed command through shell expansion."
      end

      # system("rm -rf /")
      def pattern_shell_expanding
        <<-EOT
          SendWithArguments<
            receiver  = Self | ConstantAccess<name = :Kernel>,
            name      = :` | :exec | :system | :spawn,
            arguments = ActualArguments<array = [any]>
          >
        EOT
      end

      # IO.popen
      # IO.popen3
      def pattern_popen
        <<-EOT
          SendWithArguments<
            name ^= :popen,
            arguments = ActualArguments<array = [any]>
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
