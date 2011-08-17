module Scanny
  module Checks
    # Checks for methods executing external commands that pass the command
    # through shell expansion. This can cause unwanted code execution if the
    # command includes unescaped input.
    class ShellExpandingMethodsCheck < Check
      SHELL_EXPANDING_METHODS = [:`, :exec, :system]

      def pattern
        'SendWithArguments<receiver = Self | ConstantAccess<name = :Kernel> >'
      end

      def check(node)
        return unless SHELL_EXPANDING_METHODS.include?(node.name)
        # The command goes through shell expansion only if it is passed as one
        # argument.
        return unless node.arguments.size == 1

        issue :high, "The \"#{node.name}\" method passes the executed command through shell expansion.",
              :cwe => [88, 78]
      end
    end
  end
end
