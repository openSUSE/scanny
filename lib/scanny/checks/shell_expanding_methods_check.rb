module Scanny
  module Checks
    # Checks for methods executing external commands that pass the command
    # through shell expansion. This can cause unwanted code execution if the
    # command includes unescaped input.
    class ShellExpandingMethodsCheck < Check
      def pattern
        [
          pattern_shell_expanding,
          pattern_shell_execute,
          pattern_popen,
          pattern_execute_string
        ].join("|")
      end

      def check(node)
        if Machete.matches?(node, pattern_shell_expanding)
          # The command goes through shell expansion only if it is passed as one
          # argument.
          message = "The \"#{node.name}\" method passes the executed command through shell expansion."
        else
          message = "Execute system commands can lead the system to run dangerous code"
        end

        issue :high, message, :cwe => [88, 78]
      end

      # system("rm -rf /")
      def pattern_shell_expanding
        <<-EOT
          SendWithArguments<
            receiver  = Self | ConstantAccess<name = :Kernel>,
            name      = :` | :exec | :system,
            arguments = ActualArguments<array = [any]>
          >
        EOT
      end

      # Kernel.spawn("ls -lA")
      def pattern_shell_execute
        "SendWithArguments<name = :system | :spawn | :exec>"
      end

      # IO.popen
      # IO.popen3
      def pattern_popen
        "SendWithArguments<name ^= :popen>"
      end

      # `system_command`
      def pattern_execute_string
        "ExecuteString"
      end
    end
  end
end
