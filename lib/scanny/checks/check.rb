module Scanny
  module Checks
    class Check
      def visit(file, node)
        @file = file
        @line = node.line
        @issues = []
        @node = node

        check(node)

        @issues
      end

      # @return [String] pattern used to find relevant nodes. It must respect Machete's syntax.
      def pattern
        raise "The Check class requires its childrens to provide an "\
              "implementation of the 'pattern' method."
      end

      def issue(impact, message, options = {})
        @issues << Issue.new(@file, @line, impact, message, options[:cwe])
      end

      def impact(impact)
        @impact = impact
        yield
      end

      def report_issue(pattern, options = {})
        if Machete.matches?(@node, pattern)
          issue @impact, warning_message, :cwe => options[:cwe]
        end
      end
    end
  end
end
