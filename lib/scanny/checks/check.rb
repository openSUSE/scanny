require 'scanny/issue'

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

      def issue(impact, message)
        @issues << Issue.new(@file, @line, impact, message)
      end
    end
  end
end
