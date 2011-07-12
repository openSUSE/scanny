require 'scanny/checks/check'

module Scanny
  module Checks
    # Checks for methods executing external commands that can pass the command
    # through shell expansion. This can cause unwanted code execution if the
    # command includes unescaped input.
    class ShellExpansionCheck < Check
      SHELL_EXPANDING_METHODS = [:exec, :system]

      def interesting_nodes
        [:call]
      end

      def evaluate_start_call(node)
        name = node[2]

        if SHELL_EXPANDING_METHODS.include?(name)
          add_issue "The \"#{name}\" method can pass the executed command through shell exapnsion."
        end
      end

      def evaluate_end_call(node)
        # Nothing to do.
      end
    end
  end
end
