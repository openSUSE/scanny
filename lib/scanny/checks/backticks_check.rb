module Scanny
  module Checks
    # Checks for backticks and %x{...} that pass the command through shell
    # expansion. This can cause unwanted code execution if the command includes
    # unescaped input.
    class BackticksCheck < Check
      def pattern
        'ExecuteString | DynamicExecuteString'
      end

      def check(node)
        issue :high, "Backticks and %x{...} pass the executed command through shell expansion. (CWE-88,CWE-78)"
      end
    end
  end
end
