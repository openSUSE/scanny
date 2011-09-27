module Scanny
  module Checks
    # Checks for methods executing external commands that pass the command
    # through shell expansion. This can cause unwanted code execution if the
    # command includes unescaped input.
    class ShellExpandingMethodsCheck < Check
      def pattern
        <<-EOT
          SendWithArguments<
            receiver  = Self | ConstantAccess<name = :Kernel>,
            name      = :` | :exec | :system,
            arguments = ActualArguments<array = [any]>
          >
        EOT
      end

      def check(node)
        # The command goes through shell expansion only if it is passed as one
        # argument.
        issue :high, "The \"#{node.name}\" method passes the executed command through shell expansion.",
              :cwe => [88, 78]
      end
    end
  end
end
