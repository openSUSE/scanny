module Scanny
  module Checks
    # Checks for methods executing external commands that pass the command
    # through shell expansion. This can cause unwanted code execution if the
    # command includes unescaped input.
    class ShellExpansionCheck < Check
      SHELL_EXPANDING_METHODS = [:`, :exec, :system]

      def interesting_nodes
        %w(send_with_arguments execute_string dynamic_execute_string)
      end

      def evaluate_node(node)
        if node.is_a?(Rubinius::AST::ExecuteString) || node.is_a?(Rubinius::AST::DynamicExecuteString)
          add_issue :high, "Backticks and %x{...} pass the executed command through shell exapnsion."
        else
          return unless SHELL_EXPANDING_METHODS.include?(node.name)
          # The command goes through shell exapnsion only if it is passed as one
          # argument.
          return unless node.arguments.size == 1
          unless node.receiver.is_a?(Rubinius::AST::Self) ||
              (node.receiver.is_a?(Rubinius::AST::ConstantAccess) && node.receiver.name == :Kernel)
            return
          end

          add_issue :high, "The \"#{node.name}\" method can pass the executed command through shell exapnsion."
        end
      end
    end
  end
end
