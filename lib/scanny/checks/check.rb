module Scanny
  module Checks
    class Check
      def visit(file, node)
        @file = file
        @line = node.line
        @issues = []

        check(node)

        @issues
      end

      def issue(impact, message, options = {})
        @issues << Issue.new(@file, @line, impact, message, options[:cwe])
      end
    end
  end
end
