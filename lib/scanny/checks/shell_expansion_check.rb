require 'scanny/checks/check'

module Scanny
  module Checks
    # Checks for methods executing external commands that pass the command
    # through shell expansion. This can cause unwanted code execution if the
    # command includes unescaped input.
    class ShellExpansionCheck < Check
      SHELL_EXPANDING_METHODS = [:`, :exec, :system]

      def interesting_nodes
        [:call]
      end

      def evaluate_start_call(node)
        receiver = node[1]
        name     = node[2]
        args     = node[3][1..-1]

        return unless SHELL_EXPANDING_METHODS.include?(name)
        # The command goes through shell exapnsion only if it is passed as one
        # argument.
        return unless args.size == 1
        return unless receiver.nil? || receiver == Sexp.new(:const, :Kernel)

        add_issue :high, "The \"#{name}\" method can pass the executed command through shell exapnsion."
      end

      def evaluate_end_call(node)
        # Nothing to do.
      end
    end
  end
end
