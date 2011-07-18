#TODO: get the code work with melbourne
module Scanny
  module Checks
    # Checks for methods executing external commands that pass the command
    # through shell expansion. This can cause unwanted code execution if the
    # command includes unescaped input.
    class ShellExpansionCheck < Check
      SHELL_EXPANDING_METHODS = [:`, :exec, :system]

      def interesting_nodes
        [:call, :xstr, :dxstr]
      end

      def evaluate_node(node)
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

      def evaluate_start_xstr(node)
        add_issue :high, "Backticks and %x{...} pass the executed command through shell exapnsion."
      end

      def evaluate_end_xstr(node)
        # Nothing to do.
      end

      def evaluate_start_dxstr(node)
        add_issue :high, "Backticks and %x{...} pass the executed command through shell exapnsion."
      end

      def evaluate_end_dxstr(node)
        # Nothing to do.
      end
    end
  end
end
